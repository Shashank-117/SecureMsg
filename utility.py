from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def hkdf(secret, length=32, salt=b''):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=None,
    ).derive(secret)

def kdf_root_chain(root_key, dh_output):
    new_root_key = hkdf(root_key + dh_output)
    chain_key = hkdf(new_root_key)
    return new_root_key, chain_key

def kdf_chain_key(chain_key):
    message_key = hkdf(chain_key)
    new_chain_key = hkdf(message_key)
    return new_chain_key, message_key
