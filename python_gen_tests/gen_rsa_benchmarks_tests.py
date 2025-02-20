from Crypto.PublicKey import RSA
from Crypto.Hash import BLAKE2b
from Crypto.Signature import pkcs1_15
from hexbytes import HexBytes
import base64
import random



def b64_encode(data):
    encoded = base64.urlsafe_b64encode(data).rstrip(b'=')
    return encoded.decode('ascii')


#Make the tests vector reproductible
random.seed(a=256)
def get_rand_bytes(n):
    return random.getrandbits(n * 8).to_bytes(n, 'little')


STRING_TO_SIGN = "Pact can do RSA signatures too!!"
STRING_TO_SIGN_FALSE = "This does not match with signature"

def gen_sign_data(key_len, exponent=65537, output_b64=False):
    k = RSA.generate(key_len, e=exponent, randfunc=get_rand_bytes)
    h = BLAKE2b.new(digest_bytes=32)
    h.update(STRING_TO_SIGN.encode("ascii"))
    sig = pkcs1_15.new(k)

    if not output_b64:
        key, exp, sign = HexBytes(k.n).hex(), HexBytes(k.e).hex(), HexBytes(sig.sign(h)).hex()
    else:
        key, exp, sign = map(b64_encode, map(HexBytes, [k.n, k.e, sig.sign(h)]))


    print("""
(let ((pub-key "{:s}")
      (key-len {:d})
      (pub-exp "{:s}")
      (sig "{:s}"))
  (env-gas 0)
  (rsa.verify-pkcs1-v15 pub-key key-len pub-exp sig "{:s}")
  (print (format "Gas for KL={{}} PubExp={{}} ====> {{}}" [key-len, pub-exp, (env-gas)]))
)


      """.format(key, key_len, exp, sign, STRING_TO_SIGN, STRING_TO_SIGN_FALSE))


print('(enforce-pact-version "5.0")')
print('(load "../contracts/rsa.pact")\n')
print('(env-gasmodel "table")')
print('(env-gaslimit 10000000000000)')

for s_len in (1024, 2048, 3072, 4096):
    for exponent in (5,65537):
        gen_sign_data(s_len, exponent, False)
