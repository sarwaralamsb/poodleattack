"""
This project is developed to display the basic cryptography behind the POODLE Attack
"""

import pip
import binascii
import sys
import re
import hmac, hashlib, base64


from Cryptodome.Cipher import AES
from Cryptodome import Random

IV = Random.new().read(AES.block_size)
KEY = Random.new().read(AES.block_size)


# generating random key and iv
def randomkey():
    global IV
    IV = Random.new().read(AES.block_size)
    global KEY
    KEY = Random.new().read(AES.block_size)


# padding for the CBC cipher block
def add_padding(s):
    return (16 - len(s) % 16) * chr((16 - len(s) - 1) % 16)


# unpadding after the decryption and returning the msg, the hmac and the hmac of msg
def unpad_verifier(s):
    msg = s[0:len(s) - 32 - ord(s[len(s) - 1:]) - 1]
    hash_c = s[len(msg):-ord(s[len(s) - 1:]) - 1]
    hash_d = hmac.new(KEY, msg, hashlib.sha256).digest()
    return msg, hash_d, hash_c


# encrypting a message
def encrypt(msg):
    data = msg.encode()
    hash = hmac.new(KEY, data, hashlib.sha256).digest()
    padding = add_padding(data + hash)
    raw = data + hash + padding.encode()
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(raw)


# decrypting the message
def decrypt(enc):
    decipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext, signature_2, sig_c = unpad_verifier(decipher.decrypt(enc))

    if signature_2 != sig_c:
        return 0
    return plaintext


def split_len(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]


def runattack(plain_text):

    secret = []

    length_block = 16

    a = encrypt(plain_text)
    print("Cipher Text:", a, "\n")

    t = binascii.hexlify(encrypt(plain_text))
    original_length = len(t)
    t = 1
    while (True):
        length = len(binascii.hexlify(encrypt("a" * t + plain_text)))
        if (length > original_length):
            break
        t += 1
    save = t
    v = []

    print("\nDecrypting Starts...")
    for block in range(original_length // 32 - 2, 0, -1):
        for char in range(length_block):
            count = 0
            while True:

                randomkey()
                request = split_len(
                    binascii.hexlify(encrypt("$" * 16 + "#" * t + plain_text + "%" * (block * length_block - char))), 32)

                # change the last block with our choice
                request[-1] = request[block]

                # sending the request
                cipher = binascii.unhexlify(b''.join(request).decode())
                plain = decrypt(cipher)
                count += 1

                if plain != 0:
                    t += 1
                    pbn = request[-2]
                    pbi = request[block - 1]
                    decipher_byte = chr(int("0f", 16) ^ int(pbn[-2:], 16) ^ int(pbi[-2:], 16))
                    secret.append(decipher_byte)
                    tmp = secret[::-1]
                    sys.stdout.write(
                        "\r-> Byte found '%s' - Block %d : [%16s]" % (decipher_byte, block, ''.join(tmp)))
                    sys.stdout.flush()
                    break
        print('')
        secret = secret[::-1]
        v.append(('').join(secret))
        secret = []
        t = save

    v = v[::-1]
    plaintext = re.sub('^#+', '', ('').join(v))
    print("\nDecrypted text:", plaintext)
    return v


if __name__ == '__main__':

    print("\n**** Cryptography Behind The Poodle Attack ****\n")

    plaintext = "This is the plain text for executing the Poodle Attack"
    print("Plaintext :", plaintext)
    print("Encryption Standard: AES-256 MODE_CBC")
    runattack(plaintext)


