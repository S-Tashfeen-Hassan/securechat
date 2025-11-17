# **SecureChat – Assignment #2 (Information Security – Fall 2025)**

**Author:** Tashfeen Hassan
**Roll Number:** 22i-0860
**Course:** Information Security

# **SecureChat – Encrypted Messaging System**

SecureChat is an end-to-end encrypted communication system built using Python.
It implements modern cryptographic techniques—including **AES**, **Diffie-Hellman key exchange**, and **PKI certificates**—to ensure confidentiality, integrity, and authentication across client–server communication.

---

## 📌 **Features**

### 🔐 End-to-End Encryption

* AES symmetric encryption for message confidentiality.
* Diffie-Hellman key exchange to derive shared session keys.
* Public Key Infrastructure (PKI) for certificate-based identity verification.

### 🧾 Secure Message Handling

* Encrypted message transmission between client and server.
* Structured protocol for sending, receiving, and parsing packets.

### 🗂️ Data Storage

* Local transcript storage for delivered/received messages.
* SQLite database backend (via `storage/db.py`) for persistent logging.

### 🧰 Modular Architecture

* `crypto/` for all cryptographic primitives.
* `common/` for protocol and shared utilities.
* `storage/` for transcripts and database logic.
* `app/` for server and client implementations.

### 🔏 Certificate Authority Included

* Scripts for generating your own CA and certificates.
* Pre-generated sample certificates in `certs/`.

---

## 📁 **Project Structure**

```
securechat-main/
│
├── app/
│   ├── client.py          # Client application
│   ├── server.py          # Server application
│   ├── helper.py          # Utility functions for networking
│   ├── common/
│   │   ├── protocol.py    # Message protocol definitions
│   │   └── utils.py       # Common helpers
│   ├── crypto/
│   │   ├── aes.py         # AES encryption
│   │   ├── dh.py          # Diffie-Hellman exchange
│   │   └── pki.py         # PKI certificate handling
│   └── storage/
│       ├── db.py          # Database for logs/transcripts
│       └── transcript.py  # Local transcript management
│
├── certs/                 # Certificates and keys
│
├── scripts/
│   ├── gen_ca.py          # Generate Certificate Authority
│   └── gen_cert.py        # Generate server/client certificates
│
├── tests/
│   └── manual/            # Manual testing notes
│
├── requirements.txt       # Python dependencies
└── README.md              # (This file)
```

---

## 🚀 **Getting Started**

### **1. Install Dependencies**

```
pip install -r requirements.txt
```

### **2. Generate Certificates (optional)**

If you want new certificates:

```
python scripts/gen_ca.py
python scripts/gen_cert.py server
python scripts/gen_cert.py client
```

This will create new private keys and signed certificates under `certs/`.

---

## ▶️ **Running the Server**

```
python app/server.py
```

Server listens for incoming client connections, performs certificate authentication, negotiates session keys, and manages message routing.

---

## 💬 **Running the Client**

```
python app/client.py
```

The client will:

* Load its certificate.
* Verify the server certificate.
* Perform Diffie-Hellman key exchange.
* Start sending and receiving encrypted messages.

---

## 🔒 **Security Overview**

| Component             | Technique                                         |
| --------------------- | ------------------------------------------------- |
| Symmetric Encryption  | AES (CBC/CTR depending on implementation)         |
| Key Exchange          | Diffie-Hellman                                    |
| Identity Verification | X.509 Certificates (PKI)                          |
| Message Integrity     | HMAC / AES authenticated mode (depending on code) |
| Storage Protection    | Local transcripts + optional DB                   |

---

## 🧪 **Testing**

Manual test notes can be found under:

```
tests/manual/NOTES.md
```

You may run the server in one terminal and multiple clients in others to simulate messaging between users.

---

## 🛠️ **Future Improvements**

* GUI client (Tkinter / Qt).
* Multi-user broadcast support.
* Perfect forward secrecy (via ephemeral DH keys).
* Certificate revocation lists (CRL) and OCSP.

---

## 📄 License

This project is provided for educational and research purposes.

---

If you want this README automatically placed into a file or want a more visually styled version (badges, emoji headers, diagrams, etc.), just tell me!
