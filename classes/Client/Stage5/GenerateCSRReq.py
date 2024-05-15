import os
import datetime
import OpenSSL.crypto
from termcolor import colored, cprint
from Crypto.PublicKey import RSA
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from OpenSSL.crypto import load_publickey, load_privatekey, FILETYPE_PEM, verify, X509


class GenerateCSRReq:
    home = "classes/Client/CSR"

    def __init__(self, drName):
        self.drName = drName
        self.CSRPath = self.home + "/" + drName + '-' + \
            str(datetime.datetime.now().date()) + '.csr'

    def generate(self):
        with open("ca_public_key.pem", 'rb') as file:
            ca_pk = file.read()
        with open("classes/Client/public.pem", 'rb') as f:
            pk = f.read().decode()
        with open("classes/Client/private.pem", 'rb') as f:
            pvKey = f.read().decode()
        caPK = load_publickey(crypto.FILETYPE_PEM, ca_pk)
        publicKey = load_publickey(crypto.FILETYPE_PEM, pk)
        privateKey = load_privatekey(crypto.FILETYPE_PEM, pvKey)

        country = input('Enter your country code(ex. US): ')
        state = input("Enter your state(ex. Nevada): ")
        city = input("Enter your location(City): ")
        organization = input("Enter your organization: ")
        orgUnit = input("Enter your organizational unit(ex. IT): ")
        req = crypto.X509Req()
        req.get_subject().CN = self.drName
        req.get_subject().C = country
        req.get_subject().ST = state
        req.get_subject().L = city
        req.get_subject().O = organization
        req.get_subject().OU = orgUnit

        req.set_pubkey(publicKey)
        # Sign the CRT Req
        req.sign(privateKey, "sha256")
        if not os.path.isdir(self.home):
            os.mkdir(self.home)
        with open(self.CSRPath, 'wb') as file:
            file.write(crypto.dump_certificate_request(
                crypto.FILETYPE_PEM, req))
        print(colored("Generating CSR Success!", "green"))
        return self.CSRPath
