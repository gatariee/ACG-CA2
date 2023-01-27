from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import datetime
private_key = "server_private.pem"
out_name = "server_cert.crt"
with open(private_key, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b"server",
        backend=default_backend()
    )
builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"Client 2205513"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Singapore Polytechnic"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"DISM/FT/1B/05"),
]))
builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"CA 2205513"),
]))
builder = builder.public_key(private_key.public_key())
builder = builder.serial_number(x509.random_serial_number())
builder = builder.not_valid_before(datetime.datetime.utcnow())
builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
builder = builder.add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"2205513.local")]),
    critical=False
)
certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(),
    backend=default_backend()
)
with open(out_name, "wb") as cert_file:
    cert_file.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))
