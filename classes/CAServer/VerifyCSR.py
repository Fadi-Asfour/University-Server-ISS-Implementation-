import os
import datetime
import sqlite3
from termcolor import colored, cprint
from Crypto.PublicKey import RSA
from classes.Helpers.auth import auth
from OpenSSL import crypto


class VerifyCSR:
    def __init__(self, userPk, csr, code):
        self.home = "classes/CASever/CRT_Files"
        self.csr = csr
        self.code = code
        self.userPK = userPk
        self.crtpath = self.home + str(datetime.datetime.now().date()) + '.crt'

    def verifyCSR(self):
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, self.csr)
        try:
            crypto.X509().verify(csr)
        except crypto.X509StoreContextError:
            return False
        public_key = csr.get_pubkey()
        if public_key is None:
            return False
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM userdata WHERE public_key=?",
                    ("".join(line.strip()
                             for line in self.userPK.splitlines()),))
        if not cur.fetchone():
            return "User public_key not found: ErrorCode 400"
        code = int(self.code) + 5
        user = auth().getUserByPK(self.userPK)
        cur.execute("SELECT * FROM doctors_csr_verification WHERE key_role=? AND user_name = ?",
                    (code, user.name))
        if not cur.fetchone():
            conn.commit()
            conn.close()
            return False
        conn.commit()
        conn.close()
        return True
