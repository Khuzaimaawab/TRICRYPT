from flask import Flask, render_template, request
import base64
import hashlib
import codecs
from caesarcipher import CaesarCipher
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

def aes_encrypt_simple(plaintext: str, passphrase: str = "demo-passphrase") -> str:

    key = hashlib.sha256(passphrase.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    result = base64.b64encode(cipher.iv + ciphertext).decode()
    return result

def aes_decrypt_simple(ciphertext_b64: str, passphrase: str = "demo-passphrase") -> str:
    key = hashlib.sha256(passphrase.encode()).digest()
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size).decode()
    return plaintext

def rsa_encrypt_simple(plaintext: str):

    publicKey, privateKey = rsa.newkeys(2048)

    encrypted = rsa.encrypt(plaintext.encode(), publicKey)
    
    
    result = (
        "-----BEGIN PUBLIC KEY-----\n" +
        publicKey.save_pkcs1().decode() +
        "\n-----BEGIN PRIVATE KEY-----\n" +
        privateKey.save_pkcs1().decode() +
        "\n-----BEGIN CIPHERTEXT-----\n" +
        base64.b64encode(encrypted).decode() +
        "\n-----END CIPHERTEXT-----"
    )
    return result

def rsa_decrypt_simple(combined_input: str) -> str:

    priv_start = combined_input.find("-----BEGIN PRIVATE KEY-----")
    priv_end = combined_input.find("-----END RSA PRIVATE KEY-----")
    if priv_start == -1:
        raise ValueError("Private key not found")
    
    priv_pem = combined_input[priv_start:priv_end+30]
    privateKey = rsa.PrivateKey.load_pkcs1(priv_pem.encode())
    

    ct_start = combined_input.find("-----BEGIN CIPHERTEXT-----")
    ct_end = combined_input.find("-----END CIPHERTEXT-----")
    ct_b64 = combined_input[ct_start+27:ct_end].strip()
    

    encrypted = base64.b64decode(ct_b64)
    decrypted = rsa.decrypt(encrypted, privateKey).decode()
    return decrypted

def process_text(text, method, operation, key=""):
    result = ""
    try:
        if method == 'base64':
            result = base64.b64encode(text.encode()).decode() if operation == 'encrypt' else base64.b64decode(text.encode()).decode()
        
        elif method == 'caesar':
            cipher = CaesarCipher(text, offset=3)
            result = cipher.encoded if operation == 'encrypt' else cipher.decoded
        
        elif method == 'rot13':
            result = codecs.encode(text, 'rot_13')
        
        elif method == 'reverse':
            result = text[::-1]
        
        elif method == 'binary':
            if operation == 'encrypt':
                result = ' '.join(format(ord(char), '08b') for char in text)
            else:
                result = ''.join(chr(int(b, 2)) for b in text.split())
        
        elif method == 'hex':
            result = text.encode().hex() if operation == 'encrypt' else bytes.fromhex(text).decode()
        
        elif method == 'md5':
            result = hashlib.md5(text.encode()).hexdigest()
        
        elif method == 'sha256':
            result = hashlib.sha256(text.encode()).hexdigest()
        
        elif method == 'aes':
            passphrase = key if key else "demo-passphrase"
            result = aes_encrypt_simple(text, passphrase) if operation == 'encrypt' else aes_decrypt_simple(text, passphrase)
        
        elif method == 'rsa':
            result = rsa_encrypt_simple(text) if operation == 'encrypt' else rsa_decrypt_simple(text)
        
        else:
            result = "Unknown method"
    
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    output = ""
    input_text = ""
    current_tab = "home"
    aes_key = ""
    
    if request.method == 'POST':
        input_text = request.form.get('input_text', '')
        method = request.form.get('method', 'base64')
        operation = request.form.get('operation', 'encrypt')
        current_tab = request.form.get('current_tab', 'encrypt')
        aes_key = request.form.get('aes_key', '')
        
        if input_text:
            output = process_text(input_text, method, operation, aes_key)
        else:
            output = "Please enter some text!"
    
    return render_template('index.html', 
                         output=output, 
                         input_text=input_text,
                         current_tab=current_tab,
                         aes_key=aes_key)

if __name__ == '__main__':
    app.run(debug=True, port=5555)