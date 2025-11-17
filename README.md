# **SecureChat – Assignment #2 (Information Security – Fall 2025)**

**Author:** Tashfeen Hassan
**Roll Number:** 22i-0860
**Course:** Information Security

# **SecureChat – Encrypted Messaging System**

SecureChat is an end-to-end encrypted client–server chat system built in Python.
It combines **AES symmetric encryption**, **Diffie–Hellman key exchange**, and **PKI-based certificate authentication** to ensure secure message exchange.

---

## 🌐 **GitHub Repository**

👉 **GitHub Repo:** [https://github.com/S-Tashfeen-Hassan/securechat](https://github.com/S-Tashfeen-Hassan/securechat)

---

# 📁 **Project Structure**

```
securechat/
│
├── app/
│   ├── client.py
│   ├── server.py
│   ├── helper.py
│   ├── common/
│   │   ├── protocol.py
│   │   └── utils.py
│   ├── crypto/
│   │   ├── aes.py
│   │   ├── dh.py
│   │   └── pki.py
│   └── storage/
│       ├── db.py
│       └── transcript.py
│
├── certs/                 # Certificates + private keys
├── scripts/               # Certificate generation scripts
│   ├── gen_ca.py
│   └── gen_cert.py
│
├── tests/
│   └── manual/
│       └── NOTES.md
│
├── requirements.txt
└── README.md
```

---

# ⚙️ **Prerequisites**

Before running the system, ensure the following:

### **Required Software**

* Python **3.10+**
* OpenSSL installed (for generating certificates)
* pip (Python package manager)

### **Install Dependencies**

```bash
pip install -r requirements.txt
```

---

# 🔧 **Configuration Required**

### **1. Environment Variables**

Create a file named `.env` in the project root:

```
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
CLIENT_CERT=certs/client.cert.pem
CLIENT_KEY=certs/client.key.pem
SERVER_CERT=certs/server.cert.pem
CA_CERT=certs/ca.cert.pem
```

*(Modify paths if needed.)*

---

### **2. Certificate Setup**

SecureChat uses PKI authentication.
You may **use the pre-generated certificates** in the `certs/` folder, or generate new ones.

#### **Generate a Certificate Authority (CA)**

```bash
python scripts/gen_ca.py
```

#### **Generate Server Certificate**

```bash
python scripts/gen_cert.py server
```

#### **Generate Client Certificate**

```bash
python scripts/gen_cert.py client
```

This will place signed certificates inside `certs/`.

---

# ▶️ **How to Run the System**

## **Start the Server**

```bash
python app/server.py
```

Expected output:

```
[SERVER] Listening on 127.0.0.1:5000
[SERVER] Waiting for client connection...
```

---

## **Start the Client**

```bash
python app/client.py
```

Expected output:

```
[CLIENT] Connecting to server...
[CLIENT] Certificate verified.
[CLIENT] Shared session key established.
You can now send encrypted messages.
```

---

# 💬 **Sample Input/Output**

### **Client Input**

```
hello server
```

### **Client Output**

```
[ENC SENT] b'\x93\x10\xfa...'
```

### **Server Output**

```
[RECEIVED DECRYPTED] hello server
```

### **Server Replies**

```
[SERVER] Enter message: hi client!
```

### **Client Receives**

```
[DECRYPTED] hi client!
```

---

# 🔒 **Security Features**

| Feature           | Description                      |
| ----------------- | -------------------------------- |
| AES Encryption    | Protects message confidentiality |
| Diffie–Hellman    | Secure session key negotiation   |
| PKI Certificates  | Ensures identity authenticity    |
| Encrypted Storage | Secure transcript saving         |
| Custom Protocol   | Structured packet handling       |

---

# 🧪 **Testing**

You can test by running:

* **One server**
* **Multiple clients**

Manual testing notes are available at:

```
tests/manual/NOTES.md
```

---

# 📌 **Future Improvements**

* GUI-based chat client
* Group chat and broadcast channels
* Perfect Forward Secrecy (Ephemeral DH)
* Certificate Revocation Lists (CRL)

---

# 📄 **License**

This project is for educational and secure communication research purposes.
