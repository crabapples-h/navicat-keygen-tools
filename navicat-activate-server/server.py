#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys, ssl, base64, json, time, gzip

from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

openssl_lib = crypto._lib

def RSAPublicEncrypt(key, msg: bytes):
    enc = bytes((key.key_size + 7) // 8)
    length = openssl_lib.RSA_public_encrypt(len(msg), msg, enc, key._rsa_cdata, openssl_lib.RSA_PKCS1_PADDING)
    if (length == -1):
        raise ValueError('Public encrypt failure.')
    return enc[:length]

def RSAPublicDecrypt(key, enc: bytes):
    msg = bytes((key.key_size + 7) // 8)
    length = openssl_lib.RSA_public_decrypt(len(enc), enc, msg, key._rsa_cdata, openssl_lib.RSA_PKCS1_PADDING)
    if (length == -1):
        raise ValueError('Public decrypt failure.')
    return msg[:length]

def RSAPrivateEncrypt(key, msg: bytes):
    enc = bytes((key.key_size + 7) // 8)
    length = openssl_lib.RSA_private_encrypt(len(msg), msg, enc, key._rsa_cdata, openssl_lib.RSA_PKCS1_PADDING)
    if (length == -1):
        raise ValueError('Private encrypt failure.')
    return enc[:length]

def RSAPrivateDecrypt(key, enc: bytes):
    msg = bytes((key.key_size + 7) // 8)
    length = openssl_lib.RSA_private_decrypt(len(enc), enc, msg, key._rsa_cdata, openssl_lib.RSA_PKCS1_PADDING)
    if (length == -1):
        raise ValueError('Private decrypt failure.')
    return msg[:length]

def LoadKey(path: str):
    with open(path, 'rb') as f:
        key = serialization.load_pem_private_key(f.read(), None, default_backend())
    return key

class NavicatActivateServerHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write('This is an activation server for Navicat.'.encode())

    def do_POST(self):
        print('-' * 32)
        print(self.headers)
        body = self.rfile.read(int(self.headers['Content-Length'], 0))
        print('Receive a POST request from %s:%d -->' % self.client_address)
        print(body)
        if (body.startswith(b'input:')):
            enc = body[6:]
            try:
                snKey = RSAPrivateDecrypt(prikey, enc).decode()
                print('snKey = %s' % snKey)
                license = {}
                license['K'] = snKey
                license['DI'] = 'fjavsmSJmOssbuo4Ns9H'
                license['N'] = 'DoubleLabyrinth'
                license['O'] = 'DoubleLabyrinth'
                license['T'] = 1545208026
                license['M'] = 'MMMMMMMM'
                license['FA'] = 'FAFAFAFA'
                license = json.dumps(license).encode()
                print(license)
                data = gzip.compress(RSAPrivateEncrypt(prikey, license))
                self.send_response(200)
                self.send_header('Vary', 'Accept-Encoding')
                self.send_header('Content-Encoding', 'gzip')
                self.send_header('Content-Type', 'text/html; charset=UTF-8')
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)
                print('sent...')
                print()
            except:
                self.send_response(404)
                self.end_headers()
                pass

IP = '0.0.0.0'
Port = 443
prikey = LoadKey(sys.argv[1])

httpd = HTTPServer((IP, Port), NavicatActivateServerHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, 
                               keyfile = 'cert-key.pem', 
                               certfile = 'cert-crt.pem', 
                               server_side = True)
httpd.serve_forever()

