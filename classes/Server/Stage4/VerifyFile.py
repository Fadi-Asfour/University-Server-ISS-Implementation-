import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from classes.Helpers.auth import auth as authHelper
from datetime import datetime
import sqlite3
from classes.Server.Models.User import User


class VerifyMessage:

    def __init__(self, publicKey, data, sig_file_path):
        self.publicKey = publicKey
        self.data = data
        self.sig_file = str(sig_file_path).replace("\\", "/")

    def verify_signature(self):
        auth = authHelper()
        # Check if user exists

        user = auth.getUserByPK("".join(line.strip()
                                for line in self.publicKey.splitlines()))
        if not user:
            return "Unauthenticated ErrorCode : 401"
        # Check user role
        # if user.role != "Teacher": TODO: Uncomment
        #     return "unAuthorized ErrorCode : 403"
        # Create a hash for the date
        with open(self.data, 'rb') as f:
            content = f.read()
        hash = SHA256.new(content)
        # Create rsa using client private key
        rsa = RSA.importKey(self.publicKey)
        # Create a signer to verify the sig_file
        signer = PKCS1_v1_5.new(rsa)
        # 1- open the sig_file and read it
        # 2- Check if signer can verify the hashed data with the sig_file
        # 3- If the file is verified print success else print failed
        sigfile = self.sig_file

        with open(sigfile, 'rb') as f:
            signature = f.read()
        message = "Success" if (signer.verify(hash, signature)
                                ) else "Failed"
        # insert row into files_verification table
        con = sqlite3.connect('./userdata.db')
        cur = con.cursor()

        if (message == "Success"):
            message = 'Verification Success!'
            is_success = 1
        else:
            message = 'Verification Success! ErrorCode = 400'
            is_success = 0

        cur.execute("INSERT INTO files_verifications (is_success , created_at, file_path,user_id) VALUES (? , ?, ?, ?)",
                    (is_success, str(datetime.now()), self.data, user.id))
        con.commit()
        con.close()
        return message
