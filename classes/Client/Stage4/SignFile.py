import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import random
import string
from termcolor import colored, cprint


class SignMesssage:
    def __init__(self, privateKey, data):
        self.privateKey = privateKey
        self.data = data

    def generate_signature(self):  # Client private key
        print("Generating Signature ...")
        try:
            # Create a hash for the date
            with open(self.data, 'rb') as f:
                self.data = f.read()
            hash = SHA256.new(self.data)
            # Create rsa using client private key
            rsa = RSA.importKey(self.privateKey)
            # Create an signer to sign data
            signer = PKCS1_v1_5.new(rsa)
            # Sign the hashed data and write it to signatured file (sig_f)
            signature = signer.sign(hash)
            # generate lowercase random
            letters = string.ascii_lowercase
            randomString = ''.join(random.choice(letters)
                                   for i in range(10))
            if not os.path.isdir('./Temp'):
                os.mkdir("./Temp")
            sigFileName = "Temp/sig_file_" + randomString + ".sig"
            f = open(sigFileName, "w")
            with open(sigFileName, 'wb') as file:
                file.write(signature)
            print("Generating Success ...")

            return os.path.abspath(sigFileName)
        except FileNotFoundError:
            print("The specified file was not found.")
            return False
