from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
def load_pem_cert(path_bytes):
    if isinstance(path_bytes, (bytes, bytearray)):
        data = bytes(path_bytes)
    else:
        with open(str(path_bytes), "rb") as f:
            data = f.read()
    return x509.load_pem_x509_certificate(data)

def load_pem_privkey(path, password = None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)
    
def cert_pubkey(cert: x509.Certificate):
    return cert.public_key()

def verify_sign(cert: x509.Certificate, issuer_certificate: x509.Certificate):
    issuerPub = issuer_certificate.public_key()
    try:
        issuerPub.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm
        )
        return True, ""
    except Exception as e:
        return False, f"bad signature: {e}"
    
def check_validity(cert: x509.Certificate):
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before:
        return False, f"not yet valid (not_before={cert.not_valid_before.isoformat()})"
    if now > cert.not_valid_after:
        return False, f"expired (not_after={cert.not_valid_after.isoformat()})"
    return True, ""

def check_cn(cert: x509.Certificate, expected_cn: str):
    if expected_cn is None:
        return True, ""
    
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        return False, "no CN in subject"
    
    if cn != expected_cn:
        return False, f"CN mismatch: got={cn} expected={expected_cn}"
    return True, ""

def verify_certificates(cert_pem_path_bytes, ca_cert_pem_path_bytes, expected_cn: str = None):
    try:
        cert = load_pem_cert(cert_pem_path_bytes)
    except Exception as e:
        return False, f"unable to parse cert: {e}"
    
    try:
        ca_certificate = load_pem_cert(ca_cert_pem_path_bytes)
    except Exception as e:
        return False, f"unable to parse CA cert: {e}"

    ok, reason = verify_sign(cert, ca_certificate)
    if not ok:
        return False, reason
    
    ok, reason = check_validity(cert)
    if not ok:
        return False, reason
    
    ok, reason = check_cn(cert, expected_cn)
    if not ok:
        return False, reason
    
    return True, ""