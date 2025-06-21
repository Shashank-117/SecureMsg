import socket, json, threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

client = socket.socket()
client.connect(('localhost', 5555))
client.sendall(b'bob\n')
client_file = client.makefile('r')

def receive_messages():
    while True:
        line = client_file.readline()
        if not line:
            break
        msg = json.loads(line.strip())
        if msg['type'] == 'encrypted':
            ciphertext = bytes.fromhex(msg['ciphertext'])
            nonce = bytes.fromhex(msg['nonce'])
            key = bytes.fromhex(msg['key'])
            aesgcm = AESGCM(key)
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                print(f'[Alice]: {plaintext.decode()} \nBob>')
            except Exception as e:
                print(f'[Bob] Decryption error: {e}')

threading.Thread(target=receive_messages, daemon=True).start()

while True:
    text = input('Bob> ')
    client.sendall((json.dumps({'type': 'message', 'target': 'alice', 'plaintext': text}) + '\n').encode())
