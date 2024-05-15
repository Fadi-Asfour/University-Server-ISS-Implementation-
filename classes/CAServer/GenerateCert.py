import os
import sqlite3
import datetime
from termcolor import colored, cprint
from Crypto.PublicKey import RSA
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from classes.Helpers.auth import auth
import OpenSSL.crypto


class generateCRT:
    def __init__(self, RsaPK, csr):
        self.home = "classes/CAServer/CRT_Files"
        self.csr = csr
        self.RsaPK = RsaPK
        self.crtpath = self.home + str(datetime.datetime.now().date()) + '.crt'

    def generate(self):
        # Load the private key file
        with open("classes/CAServer/Keys/ca_private_key.pem", 'r') as file:
            privateKey = file.read()
        # Create a private key object
        privateKeyObj = crypto.load_privatekey(crypto.FILETYPE_PEM, privateKey)
        # Load the CSR file
        csr_data = self.csr
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
        # Create a new certificate
        certificate = crypto.X509()
        certificate.set_subject(csr.get_subject())
        certificate.set_pubkey(csr.get_pubkey())
        pubKeyString = crypto.dump_publickey(
            crypto.FILETYPE_PEM, csr.get_pubkey())
        user = auth().getUserByPK("".join(line.strip()
                                          for line in self.RsaPK.splitlines()))
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()

        cur.execute("INSERT INTO dr_crt (user_id ,crt_t, created_at) VALUES (? , ?, ?)",
                    (user.id, pubKeyString, str(datetime.datetime.now())))
        conn.commit()
        conn.close()
        certificate.set_serial_number(1000)
        # Set the certificate validity period (from now to 2 years later)
        certificate.gmtime_adj_notBefore(0)
        certificate.gmtime_adj_notAfter(2 * 365 * 24 * 60 * 60)
        certificate.sign(privateKeyObj, "sha256")
        if not os.path.isdir(self.home):
            os.mkdir(self.home)
        fileName = csr.get_subject().CN + "_" + \
            str(datetime.datetime.now().date()) + ".crt"
        with open(self.home + "/" + fileName, 'wb') as file:
            file.write(crypto.dump_certificate(
                crypto.FILETYPE_PEM, certificate))
        return fileName
