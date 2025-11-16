# **SecureChat – Assignment #2 (Information Security – Fall 2025)**

**Author:** Mesam E Tamaar
**Roll Number:** 22i-1304
**Course:** Information Security

SecureChat is a fully implemented, console-based encrypted messaging system demonstrating:

* **Confidentiality** — AES-128
* **Integrity** — SHA-256
* **Authenticity** — RSA signatures + X.509 certificates
* **Replay protection** — sequence numbers + timestamps
* **Tamper evidence** — append-only transcript logs
* **Non-repudiation** — signed session receipts

All security is implemented at the **application layer** over plain TCP (no TLS/SSL).

---

## **1. Project Overview**

SecureChat implements:

* Certificate-based authentication using a custom Root CA
* A **two-stage Diffie–Hellman handshake**

  * DH-1 for AES-encrypted login/register
  * DH-2 with RSA signatures for secure chat sessions
* AES-128 (ECB) with PKCS#7 padding
* RSA PKCS#1 v1.5 signatures over SHA-256
* Sequence numbers + timestamps to prevent replay
* Canonical JSON transcript logs for audit and tamper detection
* Signed SessionReceipts for non-repudiation

The system consists of a Python client and server communicating using a custom encrypted protocol.

---

## **2. Folder Structure**

```
securechat/
├─ client.py
├─ server.py
│
├─ app/
│  ├─ common/
│  │  └─ protocol.py
│  │
│  ├─ crypto/
│  │  ├─ aes.py
│  │  ├─ dh.py
│  │  └─ pki.py
│  │
│  ├─ storage/
│     ├─ db.py
│     └─ transcript.py
│
├─ scripts/
│  ├─ gen_ca.py
│  └─ gen_cert.py
│
├─ certs/
├─ transcripts/
├─ client_receipts/
├─ server_receipts/
│
├─ requirements.txt
└─ README.md
```

---

## **3. Setup Instructions**

### **Install dependencies**

```bash
pip install -r requirements.txt
```

### **Start MySQL**

Example using Docker:

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

### **Initialize users table**

```bash
python app/storage/db.py --init
```

---

## **4. PKI Certificate Setup**

### **Generate Root CA**

```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
```

### **Generate server certificate**

```bash
python scripts/gen_cert.py --cn server.local --out certs/server
```

### **Generate client certificate**

```bash
python scripts/gen_cert.py --cn client.local --out certs/client
```

This produces:

* `certs/ca.cert.pem`
* `certs/ca.key.pem`
* `certs/server.cert.pem`
* `certs/server.key.pem`
* `certs/client.cert.pem`
* `certs/client.key.pem`

---

## **5. Running SecureChat**

### **Start server**

```bash
python -m app.server
```

### **Start client**

```bash
python -m app.client
```

Client prompts:

```
1) Register
2) Login
```

After login, the secure chat session begins.

---

## **6. Security Features (Implemented)**

### **PKI Certificate Validation**

Both client and server:

* Validate CA signature
* Check CN value
* Check certificate validity period
* Reject mismatched, expired, or self-signed certificates

---

### **Two-Stage Diffie–Hellman**

#### **DH #1 → login/register encryption**

Used to derive AES-128 key for:

* username
* email
* password

Credentials are encrypted before transmission.

#### **DH #2 → session establishment**

Public DH values are **RSA-signed** by both parties to prevent MITM.
Final session key is derived after signature verification.

---

### **Secure Messaging Protocol**

Each chat message includes:

```json
{
  "type": "msg",
  "seq": N,
  "iv": "...",
  "ct": "...",
  "mac": "...",
}
```

Properties:

* AES-128 ciphertext for confidentiality
* RSA signature for authenticity & integrity
* Sequence numbers for replay protection
* Timestamps for freshness

---

### **Transcript Logging**

Both client and server store append-only logs:

```
transcripts/transcript_client_<session>.log
transcripts/transcript_server_<session>.log
```

Each line includes:

* seqno
* timestamp
* ciphertext
* signature
* peer certificate fingerprint

A SHA-256 transcript hash is computed for non-repudiation.

---

### **Signed Session Receipts**

After chat ends, both sides create:

```
receipt = {
  "type": "receipt",
  "my_fp": "...",
  "peer_fp": "...",
  "first_seq": ...,
  "last_seq": ...,
  "transcript_sha256": "...",
  "ts": ...,
  "sig": "..."
}
```

Receipts are:

* RSA-signed
* exchanged
* verified
* saved to `client_receipts/` and `server_receipts/`

This ensures **non-repudiation**.

---


## **9. Conclusion**

The SecureChat system successfully demonstrates:

* Authenticated key exchange
* AES-encrypted messaging
* RSA signatures for integrity
* Replay attack resistance
* Tamper-evident logging
* Strong non-repudiation guarantees

