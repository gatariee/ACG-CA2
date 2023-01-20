from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
key = RSA.generate(2048)
passphrase = b"server"
private_key = key.export_key(pkcs=8, protection="scryptAndAES128-CBC", passphrase=passphrase)
with open("private.pem", "wb") as f:
    f.write(private_key)
public_key = key.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(public_key)

