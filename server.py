import sqlite3
import jsonpickle
from datetime import datetime
import socket
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from classes.Server.Stage4.VerifyFile import VerifyMessage
from classes.Server.Models.Response import Response
from classes.Server.Models.Request import Request
from classes.Client.Models.StructureSym import StructureSym
from classes.Helpers.auth import auth
import threading
import hmac
import classes.Server.Stage3.pgp_s_functions as pgp_s_functions
from termcolor import colored, cprint


# generate public and private key pair

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = "localhost"
port = 9999
server.bind((ip, port))

server.listen()

print(colored("Creating Servers Keys, Please Wait", "white", "on_magenta"))
fingerprint = pgp_s_functions.generate_key(
    'RSA', 1024, 'server@server.org', pgp_s_functions.passphrase)

print(colored("PGP Key Generated", "white", "on_blue"))
print("")

print()
print(colored("Starting server at >> " + str(ip) + ":" + str(port), "green"))
print()


def handle_connection(c):

    while True:
        option = c.recv(1024).decode()
        request = jsonpickle.decode(option)
        print(colored("Request resived at : " +
              datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "green"))
        ###
        match request.url:
            case "get_server_key":
                data = returnPublicKey(c)
                response = Response("return_server_public", data)
            case "send_info":
                data = receive_info(c, request.data, request.public_key)
                response = Response("print", data)
            case "regist_student":
                data = handle_registration_connection(
                    c, jsonpickle.decode(request.data))
                response = Response("print", data)
            case "regist_teacher":
                data = handle_registration_admin_connection(
                    c, jsonpickle.decode(request.data))
                response = Response("print", data)
            case "login":
                data = handel_login_connection(
                    c, request.public_key, jsonpickle.decode(request.data))
                response = Response("print", data)
            case "verify_sig":
                msg = handle_message_signiture(
                    client, jsonpickle.decode(request.data)).encode()
                response = Response("print", msg)
            case "send_client_SK":
                msg = recieveSK(
                    client, request.public_key, request.data).encode()
                response = Response("print", msg)
            case "store_student_projects":
                msg = stage3(
                    client, request.public_key, jsonpickle.decode(request.data)).encode()
                response = Response("print", msg)
            case _:
                response = Response("print", "Route not found! ErrorCode 404")
                print(colored("Route Not Found!", "red"))
        print(colored("Response returned at : " +
                      datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "green"))
        c.send(str(jsonpickle.encode(response)).encode())


def handle_registration_admin_connection(c, data):
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    publicKey = "".join(line.strip()
                        for line in data.public_key.splitlines())
    cur.execute("SELECT * FROM userdata WHERE username=?", (data.userName,))
    if cur.fetchone():
        return "Username already exists. Please use another ErrorCode 400"
    cur.execute("SELECT * FROM userdata WHERE public_key=?",
                (publicKey,))
    if cur.fetchone():
        return "User public_key is already used: ErrorCode 400"
    cur.execute("SELECT * FROM admindata WHERE key_role=? AND user_name = ?",
                (data.key, data.userName))
    if cur.fetchone():
        cur.execute("INSERT INTO userdata(username, password,role,national_num,public_key) VALUES (?, ?, ?, ?, ?)",
                    (data.userName, data.password, "Teacher", data.ID, publicKey))
        conn.commit()
        conn.close()
        return "Register Success!"
    conn.commit()
    conn.close()
    return "Wrong key, Registration failed ErrorCode 400"


def handle_registration_connection(c, data):
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    publicKey = "".join(line.strip()
                        for line in data.public_key.splitlines())
    cur.execute("SELECT * FROM userdata WHERE username=?", (data.userName,))
    if cur.fetchone():
        return "Username already exists. Choose a different one ErrorCode 400"
    cur.execute("SELECT * FROM userdata WHERE public_key=?",
                (publicKey,))
    if cur.fetchone():
        return "User public_key is already used: ErrorCode 400"
    cur.execute("INSERT INTO userdata(username, password,role,national_num,public_key) VALUES (?, ?, ?, ?, ?)",
                (data.userName, data.password, "Student", data.ID, publicKey))
    conn.commit()
    conn.close()
    return "Register Success!"


def handel_login_connection(c, pk, data):
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    publicKey = "".join(line.strip()
                        for line in pk.splitlines())
    user = auth().getUserByPK(publicKey)
    if not user:
        return "User not found ErrorCode 400"
    cur.execute(
        "SELECT * FROM userdata WHERE username=? AND password=?",
        (data.userName, hashlib.sha256(data.password.encode()).hexdigest()))
    if cur.fetchone():
        conn.commit()
        conn.close()
        return "Login Successful."
    conn.commit()
    conn.close()
    return "Login Failed ErrorCode 400"


def receive_info(c, data, publicKey):
    user = auth().getUserByPK(publicKey)
    if not user:
        return "User not found ErrorCode 400"
    enc = jsonpickle.decode(data)
    iv = enc.iv
    ciphertext = enc.CT
    received_mac = enc.mac  # Get the MAC from the end of the message
    key = hashlib.sha256(user.national_num.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = iv + ciphertext
    calculated_mac = hmac.new(key, message, hashlib.sha256).digest()

    if calculated_mac == received_mac:
        plaintext = unpad(cipher.decrypt(ciphertext), 16).decode()
        phone_number, mobile_number, place_of_residence = plaintext.split(",")

        # store the  information in the database
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        query = "UPDATE userdata SET phone_number = ?,mobile_number = ?, address = ? WHERE public_key = ?"
        values = (phone_number, mobile_number, place_of_residence, "".join(line.strip()
                                                                           for line in publicKey.splitlines()))
        cur.execute(query, values)
        conn.commit()
        conn.close()
        # Notify the client of success
        return "Info Added"

    else:
        return "MAC Verification Failed ErrorCode 403"


def handle_message_signiture(client, recivedData):
    return VerifyMessage(recivedData.publicKey, recivedData.data_path,
                         recivedData.sig_path).verify_signature()


def returnPublicKey(c):
    with open("server_public_key.asc", "rb") as f:
        server_public_key = f.read()
    return server_public_key.decode()


def stage3(c, pk, struct):
    enc = jsonpickle.decode(struct)
    iv = enc.iv
    ciphertext = enc.CT
    received_mac = enc.mac  # Get the MAC from the end of the message
    user = auth().getUserByPK("".join(line.strip()
                                      for line in pk.splitlines()))
    if not user:
        return "Unauthenticated ErrorCode : 401"
    if not user:
        return ("User not found! ErrorCode 404")
    sessionKey = user.sk
    hashedSession = hashlib.sha256(sessionKey.encode()).digest()[:16]
    cipher = AES.new(hashedSession, AES.MODE_CBC, iv)
    message = iv + ciphertext
    calculated_mac = hmac.new(hashedSession, message, hashlib.sha256).digest()

    if calculated_mac == received_mac:
        plaintext = unpad(cipher.decrypt(ciphertext), 16).decode()

        # store the  information in the database
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()

        cur.execute("INSERT INTO student_projects (projects ,user_id, created_at) VALUES (? , ?, ?)",
                    (plaintext, user.id, str(datetime.now())))
        conn.commit()
        conn.close()
        # Notify the client of success
        return "We get Projects Descriptions successfully"
    else:
        return "MAC Verification Failed ErrorCode 403"


def recieveSK(c, publicKey, data):
    recieved_Data = data
    print(colored("Recieve new session key", "green"))
    sessionKey = pgp_s_functions.decrypt_message(
        recieved_Data, pgp_s_functions.passphrase)
    query = "UPDATE userdata SET session_key = ? WHERE public_key = ?"
    values = (sessionKey, "".join(line.strip()
              for line in publicKey.splitlines()))
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    cur.execute(query, values)
    conn.commit()
    conn.close()
    return str("The Key accepted successfully")


while True:
    client, addr = server.accept()
    threading.Thread(target=handle_connection, args=(client,)).start()
