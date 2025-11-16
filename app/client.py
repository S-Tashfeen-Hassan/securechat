import struct
import json
import os
import socket
import secrets
import hashlib
import hmac
import base64
import threading
import time
import sys
import datetime
import queue
from app.common.protocol import Hello, json_en, json_de
from app.crypto.pki import verify_certificates, load_pem_privkey, load_pem_cert, cert_pubkey
from app.crypto.dh import gen_priv_key, pub_from_priv, derive_shared_key
from app.crypto.aes import encrypt_ecb_b64, decrypt_ecb_b64
from app.storage.transcript import append_transcript_line, compute_transcript_hash_and_bounds, cert_fingerprint_hex
from app.helper import send_msg_sock, recv_msg_sock, do_login, do_register
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes
CA_CERT = os.getenv("CA_CERT", "certs/ca.cert.pem")
CLIENT_CERT = os.getenv("CLIENT_CERT", "certs/client.cert.pem")
CLIENT_KEY = os.getenv("CLIENT_KEY", "certs/client.key.pem")
SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9000"))

def timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

SESSION_ID = timestamp()

TRANSCRIPT_DIR = "transcripts"
RECEIPT_DIR = "receipts"
os.makedirs(TRANSCRIPT_DIR, exist_ok=True)
os.makedirs(RECEIPT_DIR, exist_ok=True)

TRANSCRIPT_FILE = os.path.join(TRANSCRIPT_DIR, f"transcript_client_{SESSION_ID}.log")
OWN_RECEIPT_FILE = os.path.join(RECEIPT_DIR, f"client_receipt_{SESSION_ID}.json")
PEER_RECEIPT_FILE = os.path.join(RECEIPT_DIR, f"client_peer_receipt_{SESSION_ID}.json")

def do_handshake(sock):
    with open(CLIENT_CERT, "rb") as f:
        clientCertBytes = f.read()

    clientHello = Hello(certPem=clientCertBytes.decode("utf-8"), nonce="cli-nonce-1")
    send_msg_sock(sock, json_en(clientHello))

    raw = recv_msg_sock(sock)
    msg = json_de(raw)

    if msg.get("type") != "hello":
        raise Exception("Bad server response")

    ok, reason = verify_certificates(msg["certPem"].encode("utf-8"), CA_CERT)
    if not ok:
        raise Exception("Server cert not valid: " + reason)

    server_cert_obj = load_pem_cert(msg["certPem"].encode("utf-8"))
    server_pubkey = cert_pubkey(server_cert_obj)

    client_cert_obj = load_pem_cert(clientCertBytes)

    a = gen_priv_key()
    A = pub_from_priv(a)
    send_msg_sock(sock, json.dumps({"type": "dh_client", "A": format(A, "x")}).encode("utf-8"))

    raw = recv_msg_sock(sock)
    msg = json_de(raw)

    B = int(msg["B"], 16)

    key16 = derive_shared_key(a, B)

    return key16, server_pubkey, server_cert_obj, client_cert_obj

def do_session_dh(sock, server_pubkey):
    client_priv = load_pem_privkey(CLIENT_KEY)

    a_s = gen_priv_key()
    A_s_hex = format(pub_from_priv(a_s), "x")

    sig = client_priv.sign(A_s_hex.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig).decode("ascii")

    send_msg_sock(sock, json.dumps({"type": "dh_session", "A": A_s_hex, "sig": sig_b64}).encode("utf-8"))

    raw = recv_msg_sock(sock)
    msg = json_de(raw)

    if msg.get("type") == "error":
        print("[client] server rejected dh_session")
        return None, None

    B_hex = msg["B"]
    sigB = base64.b64decode(msg["sig"])

    try:
        server_pubkey.verify(sigB, B_hex.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        print("[client] Server signature on DH failed.")
        return None, None

    session_key = derive_shared_key(a_s, int(B_hex, 16))

    return session_key, client_priv
def chat_send_loop(sock, session_key, client_priv, send_state, own_cert_obj):
    try:
        while True:
            line = input()
            if not line:
                continue
            if line.strip() == "/quit":
                with send_state["lock"]:
                    send_state["quit"] = True
                return

            with send_state["lock"]:
                seqno = send_state["next_seq"]
                send_state["next_seq"] += 1

            ts = int(time.time() * 1000)
            ct = encrypt_ecb_b64(session_key, line.encode("utf-8"))

            msg_bytes_for_hash = f"{seqno}{ts}{ct}".encode("utf-8")
            digest = hashlib.sha256(msg_bytes_for_hash).digest()

            sig = client_priv.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
            sig_b64 = base64.b64encode(sig).decode("ascii")

            msg = {"type": "msg", "seqno": seqno, "ts": ts, "ct": ct, "sig": sig_b64}

            send_msg_sock(sock, json.dumps(msg).encode("utf-8"))
            append_transcript_line(TRANSCRIPT_FILE, seqno, ts, ct, sig_b64, own_cert_obj)
    except Exception as e:
        print("[client][send] exception:", e)

def chat_recv_loop(sock, session_key, server_pubkey, recv_state, peer_cert_obj, stop_event, receipt_q: "queue.Queue"):
    try:
        while not stop_event.is_set():
            try:
                raw = recv_msg_sock(sock)
            except Exception:
                break
            if not raw:
                break
            msg = json.loads(raw.decode("utf-8"))

            if msg.get("type") == "msg":
                seqno = msg["seqno"]
                ts = msg["ts"]
                ct = msg["ct"]
                sig_b64 = msg["sig"]
                sig = base64.b64decode(sig_b64)

                with recv_state["lock"]:
                    if seqno <= recv_state["last_seq"]:
                        print("[client] REPLAY:", seqno)
                        continue
                    recv_state["last_seq"] = seqno

                msg_bytes_for_hash = f"{seqno}{ts}{ct}".encode("utf-8")
                digest = hashlib.sha256(msg_bytes_for_hash).digest()

                try:
                    server_pubkey.verify(sig, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
                except Exception:
                    print("[client] SIG FAIL:", seqno)
                    continue

                try:
                    pt = decrypt_ecb_b64(session_key, ct)
                    print(f"[peer] ({seqno}) {pt.decode('utf-8')}")
                except Exception:
                    print("[client] decrypt fail:", seqno)
                    continue

                append_transcript_line(TRANSCRIPT_FILE, seqno, ts, ct, sig_b64, peer_cert_obj)
            elif msg.get("type") == "receipt":
                try:
                    receipt_q.put_nowait(msg)
                except Exception:
                    pass
            else:
                continue
    finally:
        stop_event.set()

def build_receipt(priv, role, transcript, my_fp, peer_fp):
    digest_hex, first_seq, last_seq = compute_transcript_hash_and_bounds(transcript)
    if digest_hex is None:
        digest_hex = ""

    ts = int(time.time() * 1000)
    sig = priv.sign(digest_hex.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig).decode("ascii")

    return digest_hex, {
        "type": "receipt",
        "peer": role,
        "my_fp": my_fp,
        "peer_fp": peer_fp,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": digest_hex,
        "ts": ts,
        "sig": sig_b64
    }


def send_receipt(sock, receipt):
    send_msg_sock(sock, json.dumps(receipt).encode("utf-8"))


def recv_and_verify_receipt_from_queue(sock, peer_pubkey, expected_peer_fp, local_hash, receipt_q: "queue.Queue", timeout=10):
    try:
        msg = receipt_q.get_nowait()
    except queue.Empty:
        try:
            msg = receipt_q.get(timeout=timeout)
        except queue.Empty:
            try:
                raw = recv_msg_sock(sock)
            except Exception as e:
                return False, None, f"receipt not received: {e}"
            try:
                msg = json.loads(raw.decode("utf-8"))
            except:
                return False, None, "bad JSON"

    if msg.get("type") != "receipt":
        return False, msg, "not a receipt"

    if msg.get("peer_fp") != expected_peer_fp:
        return False, msg, "peer FP mismatch"

    sig = base64.b64decode(msg["sig"])
    peer_hash = msg["transcript_sha256"]

    try:
        peer_pubkey.verify(sig, peer_hash.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        return False, msg, "signature invalid"

    if peer_hash != local_hash:
        return False, msg, "hash mismatch"

    return True, msg, "OK"

def main():
    print("==== SECURECHAT CLIENT ====")
    print("1) Register")
    print("2) Login")
    choice = input("Select (1/2): ").strip()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))

    try:
        key16, server_pubkey, server_cert_obj, client_cert_obj = do_handshake(sock)

        if choice == "1":
            do_register(sock, key16)
        else:
            do_login(sock, key16)

        session_key, client_priv = do_session_dh(sock, server_pubkey)

        send_state = {"next_seq": 1, "lock": threading.Lock(), "quit": False}
        recv_state = {"last_seq": 0, "lock": threading.Lock()}
        recv_stop = threading.Event()
        receipt_q = queue.Queue()

        my_fp = cert_fingerprint_hex(client_cert_obj)
        peer_fp = cert_fingerprint_hex(server_cert_obj)

        sender = threading.Thread(target=chat_send_loop, args=(sock, session_key, client_priv, send_state, client_cert_obj))
        receiver = threading.Thread(target=chat_recv_loop, args=(sock, session_key, server_pubkey, recv_state, server_cert_obj, recv_stop, receipt_q))
        sender.start()
        receiver.start()

        sender.join()
        recv_stop.set()
        receiver.join(timeout=2)

        local_hash, my_receipt = build_receipt(client_priv, "client", TRANSCRIPT_FILE, my_fp, peer_fp)
        with open(OWN_RECEIPT_FILE, "w") as f:
            json.dump(my_receipt, f, indent=2)

        send_receipt(sock, my_receipt)
        ok, peer_receipt, msg = recv_and_verify_receipt_from_queue(sock, server_pubkey, my_fp, local_hash, receipt_q, timeout=10)

        with open(PEER_RECEIPT_FILE, "w") as f:
            json.dump(peer_receipt if peer_receipt else {}, f, indent=2)

        if not ok:
            print("[client] peer receipt verification failed:", msg)
            try:
                print("[debug] local_hash:", local_hash)
                if peer_receipt:
                    print("[debug] peer_digest:", peer_receipt.get("transcript_sha256"))
            except:
                pass
        else:
            print("[client] peer receipt verified OK")

        try:
            sock.close()
        except:
            pass

    except Exception as e:
        print("[client] error:", e)
        try:
            sock.close()
        except:
            pass


if __name__ == "__main__":
    main()
