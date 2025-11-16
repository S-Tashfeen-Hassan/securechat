import struct
import json

from app.common.protocol import Hello, json_en, json_de
from app.crypto.aes import encrypt_ecb_b64, decrypt_ecb_b64

def send_msg_sock(sock, objBytes: bytes):
    length = len(objBytes)
    hdr = struct.pack("!I", length)
    sock.sendall(hdr + objBytes)

def recv_msg_sock(sock):
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("socket closed")
        hdr += chunk

    length = struct.unpack("!I", hdr)[0]

    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data += chunk
    return data


def do_register(sock, key16):
    username = input("Choose username: ").strip()
    email = input("Enter email: ").strip()
    password = input("Choose password: ").strip()

    payload = {"type": "register", "username": username, "email": email, "password": password}
    ct = encrypt_ecb_b64(key16, json.dumps(payload).encode("utf-8"))

    send_msg_sock(sock, json.dumps({"type": "enc", "ct": ct}).encode("utf-8"))

    raw = recv_msg_sock(sock)
    msg = json_de(raw)

    pt = decrypt_ecb_b64(key16, msg["ct"])
    resp = json.loads(pt.decode("utf-8"))

    print("\n[client] SERVER SAYS:", resp, "\n")

def do_login(sock, key16):
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    payload = {"type": "login", "username": username, "password": password}
    ct = encrypt_ecb_b64(key16, json.dumps(payload).encode("utf-8"))

    send_msg_sock(sock, json.dumps({"type": "enc", "ct": ct}).encode("utf-8"))

    raw = recv_msg_sock(sock)
    msg = json_de(raw)

    pt = decrypt_ecb_b64(key16, msg["ct"])
    resp = json.loads(pt.decode("utf-8"))

    print("\n[client] LOGIN RESULT:", resp, "\n")
