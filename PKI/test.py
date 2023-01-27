from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
with open("server_cert.crt", "rb") as f:
    server_cert_data = f.read()
server_cert = x509.load_pem_x509_certificate(server_cert_data, default_backend())
with open("client_test.crt", "rb") as f:
    client_test_data = f.read()
client_test_cert = x509.load_pem_x509_certificate(client_test_data, default_backend())
try:
    server_cert.public_key().verify(
        server_cert.signature,
        client_test_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        server_cert.signature_hash_algorithm,
    )
    print("Certificate verified.")
except Exception as e:
    print("Certificate verification failed:", e)
