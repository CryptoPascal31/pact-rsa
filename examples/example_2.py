from Crypto.PublicKey import RSA
from Crypto.Hash import BLAKE2b
from Crypto.Signature import pkcs1_15
import base64
import json

def b64_encode(data):
    encoded = base64.urlsafe_b64encode(data).rstrip(b'=')
    return encoded.decode('ascii')

with open("example_key.pem") as fd:
    key = RSA.import_key(fd.read())

sig = pkcs1_15.new(key)

# Object signing
EXAMPLE_OBJECT = {"account": "My_Account_Name", "index":{"int":1983}}

h = BLAKE2b.new(digest_bytes=32)
bytes_to_sign = json.dumps(EXAMPLE_OBJECT, separators=(',', ':'))
h.update(bytes_to_sign.encode())
print(b64_encode(sig.sign(h)))
