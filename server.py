import socket, threading, json, os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from utility import kdf_root_chain, kdf_chain_key

clients = {}
public_keys = {}
chains = {}
root_keys = {}

def handle_client(name, conn):
    file = conn.makefile('r')
    while True:
        line = file.readline()
        if not line:
            break
        msg = json.loads(line.strip())
        if msg['type'] == 'message':
            target = msg['target']
            plaintext = msg['plaintext'].encode()
            if name not in public_keys or target not in public_keys:
                continue

            # X3DHE
            sender_long = public_keys[name]['long']
            sender_eph = public_keys[name]['eph']
            target_long = public_keys[target]['long']
            target_eph = public_keys[target]['eph']
            shared_secret = (
                sender_long.exchange(target_long.public_key()) +
                sender_eph.exchange(target_long.public_key()) +
                sender_long.exchange(target_eph.public_key())
            )

            # Initialize or update root/send/recv chains
            if (name, target) not in chains:
                rk, send_ck = kdf_root_chain(b'', shared_secret)
                chains[(name, target)] = send_ck
                root_keys[(name, target)] = rk
            else:
                rk = root_keys[(name, target)]
                send_ck = chains[(name, target)]

            send_ck, key = kdf_chain_key(send_ck)
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            chains[(name, target)] = send_ck
            root_keys[(name, target)] = rk

            out = {
                'type': 'encrypted',
                'ciphertext': ciphertext.hex(),
                'nonce': nonce.hex(),
                'key': key.hex()
            }
            clients[target].sendall((json.dumps(out) + '\n').encode())

def main():
    s = socket.socket()
    s.bind(('localhost', 5555))
    s.listen()
    print('[SERVER] Running...')

    while True:
        conn, _ = s.accept()
        name_line = conn.recv(1024).decode().strip()
        name = name_line.lower()
        print(f'[SERVER] {name} connected')

        # Assign fresh keys for each
        longterm = x25519.X25519PrivateKey.generate()
        ephemeral = x25519.X25519PrivateKey.generate()
        public_keys[name] = {
            'long': longterm,
            'eph': ephemeral
        }
        clients[name] = conn

        threading.Thread(target=handle_client, args=(name, conn), daemon=True).start()

main()
