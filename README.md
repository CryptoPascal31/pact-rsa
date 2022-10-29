# PACT RSA Signatures
## Intro

This PACT module let smart-contracts to verify RSA signatures on the Kadena blockchain.

Due to the limitations of Pact, only a specific subset of PKCS#1 has been implemented:

- **Hash Algorithm**: Blake2B (note that Blake2 is not standardized in RFC 8017). This is the only one hash algorithm supported by Pact in native.
- **Padding**: PKCS#1 v1.5 only. Pact does not allow to work on the "bytes level". Thus PSS can't be implemented.
- **Key Size** : 1024, 2048, 3072 or 4096.


This module has been tested against the RSA implementation of PyCryptodome.

I don't know if RSA signature verification will be usefull on Kadena. But at least it demonstrates how Pact can handle big integers as well.

## Usage
```lisp
(free.rsa.verify-pkcs1-v15 pub-key key-size pub-exp sig msg)
```

where:
 - pub-key: `string` is public-key in hexa (start with `0x`) or in base64url
 - key-size: `integer` is the length of the RSA key (1024, 2048, 3072 or 4096)
 - pub-exp: `string` is the exponent of the public key in hexa (start with `0x`) or in base64url
 - sig: `string` is the signature to verify in hexa (start with `0x`) or in base64url
 - msg: `any type` is the message signed by the sender.


**Note**: We use the Pact serialization for computing the hash. If `msg` is not a string, it should be have been serialized before signing according to the *Pact rules* : https://github.com/kadena-io/pact/blob/master/src/Pact/Types/Codec.hs


## Gas Usage
| Key Size / Exp | 5      | 65537   |
|----------------|--------|---------|
| 1024           | 1,583  | 6,275   |
| 2048           | 6,021  | 24,404  |
| 3172           | 13,338 | 54,570  |
| 4096           | 23,643 | 97,079  |


## Examples
### String signature

Signature: In Python
```python
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
```
```
>>> NPDD7UjWrlcBVYeLPFW9f6tQA6-F6Sx7KOVtZi3Q6f3og3wDttfwId8887TezTpMPYeSHvEiklV2T6wl4cIFk0aa7Bfl9k3lMRopNASSStzCGOy5oXPT0GUXVMjzIdLmGKkrDS6MfhJwqVbJVu-ap4M3klqEXNo3VHhkTjN0KMg
```

Verification: Pact
```lisp
(load "../pact/contracts/rsa.pact")

(print (format "Signture Result: {}" [
(rsa.verify-pkcs1-v15 "0x00b4ebe70a0dc7e64f893b3839872881b9f7185add56abf21877d5acd8a1e9803399a638e48a79b75cbacc90562e97b59b5de0ef1f7a7cf5903dafacb62c45bd0423dd5cc097a730e0f47e58d7196149a3c6391082418763b7813b88cc8fcd0adb6bc128d6f8926d002d3306b7ba29d8d8797438a8fd1ef1a4884bca8069bfad1b"
                      1024
                      "0x10001"
                      "NPDD7UjWrlcBVYeLPFW9f6tQA6-F6Sx7KOVtZi3Q6f3og3wDttfwId8887TezTpMPYeSHvEiklV2T6wl4cIFk0aa7Bfl9k3lMRopNASSStzCGOy5oXPT0GUXVMjzIdLmGKkrDS6MfhJwqVbJVu-ap4M3klqEXNo3VHhkTjN0KMg"
                      "Hello world")
                                    ]))
```
```
Signture Result: true
Load successful
```

### Complex object signature
Signature: In Python
```python
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
```
```
>>> K_C4lpq8tTw62-3iCFNNtDu0HiBonVFV7-6VoqlFzH7tOmq1Rm5a7GioMUtEmT9bNvopLzKynYJjw6pcgwYISbUz6BiMzfQg4jK8wLaxLkaQcPlDC9Dnx2sQXocl1pKt8HiZpWDmYzPXbPPlXN-l-jYFONHXm4iubMRY_-FV8uo
```
Verification: Pact
```lisp
(load "../pact/contracts/rsa.pact")

(print (format "Signture Result: {}" [
(rsa.verify-pkcs1-v15 "0x00b4ebe70a0dc7e64f893b3839872881b9f7185add56abf21877d5acd8a1e9803399a638e48a79b75cbacc90562e97b59b5de0ef1f7a7cf5903dafacb62c45bd0423dd5cc097a730e0f47e58d7196149a3c6391082418763b7813b88cc8fcd0adb6bc128d6f8926d002d3306b7ba29d8d8797438a8fd1ef1a4884bca8069bfad1b"
                      1024
                      "0x10001"
                      "K_C4lpq8tTw62-3iCFNNtDu0HiBonVFV7-6VoqlFzH7tOmq1Rm5a7GioMUtEmT9bNvopLzKynYJjw6pcgwYISbUz6BiMzfQg4jK8wLaxLkaQcPlDC9Dnx2sQXocl1pKt8HiZpWDmYzPXbPPlXN-l-jYFONHXm4iubMRY_-FV8uo"
                      {'account:"My_Account_Name", 'index:1983})
                                    ]))

```
```
Signture Result: true
Load successful
```
