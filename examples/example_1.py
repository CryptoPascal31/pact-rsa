from Crypto.PublicKey import RSA
from Crypto.Hash import BLAKE2b
from Crypto.Signature import pkcs1_15
import base64

def b64_encode(data):
    encoded = base64.urlsafe_b64encode(data).rstrip(b'=')
    return encoded.decode('ascii')

with open("example_key.pem") as fd:
    key = RSA.import_key(fd.read())

sig = pkcs1_15.new(key)

# String signing
h = BLAKE2b.new(digest_bytes=32)
h.update(b"Hello world")
print(b64_encode(sig.sign(h)))
