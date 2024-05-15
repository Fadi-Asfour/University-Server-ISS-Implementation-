import json
import pickle
import jsonpickle
import socket
import sys
import os
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from classes.Client.Models.Register import Register
from classes.Client.Models.Login import Login as LoginReq
from classes.Client.Stage1.User import User
from classes.Client.Stage4.SignFile import SignMesssage
from classes.Server.Stage4.VerifyFile import VerifyMessage
from classes.Client.Models.StructureSym import StructureSym
from classes.Client.Models.ProjectsDesc import ProjectsDesc
from classes.Client.Models.CsrReq import csrReq
from classes.Server.Models.SignedMessage import SignedMessage
from classes.Client.Models.Request import Request
from classes.Client.Models.Response import Response
from classes.Helpers.auth import auth
import hmac
from termcolor import colored, cprint
from classes.Client.Stage5.GenerateCSRReq import GenerateCSRReq
import classes.Client.Stage3.pgp_c_functions as pgp_c_functions
import classes.Client.Stage3.rsa_c_functions as rsa_c_functions


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 9999))
    # Connect To CA
    caClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    caClient.connect(('localhost', 9998))
    # Generate Session Key
    rsa_c_functions.generate_keys(1024)
    session_key = pgp_c_functions.session_random_string(16)
    # Get Server Public Key
    getServerKeyRequest = Request("get_server_key", None, None)
    client.send(str(jsonpickle.encode(getServerKeyRequest)).encode())
    serverKeyRes = jsonpickle.decode(client.recv(1024).decode())
    if serverKeyRes.url == "return_server_public":
        returnServerPublic(serverKeyRes.data)
    # Get CA Public Key
    if not os.path.exists("ca_public_key.pem"):
        getCaKeyRequest = Request("get_PK", None, None)
        caClient.send(str(jsonpickle.encode(getCaKeyRequest)).encode())
        CaKeyRes = jsonpickle.decode(caClient.recv(1024).decode())
        if CaKeyRes.url == "return_server_public":
            StoreCaPK(CaKeyRes.data)
    ######
    while True:
        option = options()
        match option:
            case "1":
                data = register(client)
                res = client.recv(1024).decode()
            case "2":
                data = register_admin(client)
                res = client.recv(1024).decode()
            case "3":
                data = login(client)
                res = client.recv(1024).decode()
            case "4":
                data = send_info(client)
                res = client.recv(1024).decode()
            case "5":
                data = stage3(client, session_key)
                res = client.recv(1024).decode()
            case "6":
                sendSignedMessage(client)
                res = client.recv(1024).decode()
            case "7":
                GenerateCRT(client, caClient)
                res = caClient.recv(2048).decode()
            case "0":
                exit()
            case _:
                printResponse("Unknowen choice ErrorCode 400")
                continue

        response = jsonpickle.decode(res)
        match response.url:
            case "print":
                printResponse(response.data)
            case "return_server_public":
                returnServerPublic(response.data)
            case "return_ca_public":
                StoreCaPK(response.data)
            case "return_crt":
                StoreCRT(jsonpickle.decode(response.data))
            case _:
                printResponse("Something went wrong! ErrorCode 500")


def options():
    print("------------------------------------------")
    option = input("""input What to do:
    1- Register
    2- Register as a teacher
    3- Login
    4- Add account info
    5- Send Projects list (Hybird encryption)
    6- Sign Message
    7- Generate CRT
    0- Exit
Your choice : """)
    return option


def login(client):
    username = input("Enter username: ")
    password = input("Enter password: ")
    with open("classes/Client/public.pem", 'rb') as f:
        publicKey = f.read().decode()
    dataToSend = LoginReq(username, password)
    request = Request("login", publicKey,
                      jsonpickle.encode(dataToSend))
    client.send(str(jsonpickle.encode(request)).encode())
    print(colored("Sending data...", "green"))
    return True


def register_admin(client):
    username = input("Enter new username: ")
    password = input("Enter new password: ")
    nationalNumber = input("Enter national number: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    key = input("Enter verify key: ")
    with open("classes/Client/public.pem", 'rb') as f:
        publicKey = f.read().decode()
    msgToSend = Register(username, hashed_password,
                         "Teacher", nationalNumber, publicKey, key)
    request = Request("regist_teacher", publicKey,
                      jsonpickle.encode(msgToSend))
    client.send(str(jsonpickle.encode(request)).encode())
    print(colored("Sending data...", "green"))
    return True


def register(client):
    username = input("Enter new username: ")
    password = input("Enter new password: ")
    nationalNumber = input("Enter national number: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open("classes/Client/public.pem", 'rb') as f:
        publicKey = f.read().decode()

    msgToSend = Register(username, hashed_password,
                         "Student", nationalNumber, publicKey)
    request = Request("regist_student", publicKey,
                      jsonpickle.encode(msgToSend))
    client.send(str(jsonpickle.encode(request)).encode())
    print(colored("Sending data...", "green"))
    return True


def send_info(client):
    with open("classes/Client/public.pem", 'rb') as f:
        publicKey = "".join(line.strip()
                            for line in f.read().decode().splitlines())
    phone_number = input("Phone number: ")
    mobile_number = input("Mobile number: ")
    place_of_residence = input("Address: ")
    user = auth().getUserByPK(publicKey)
    key = hashlib.sha256(user.national_num.encode()).digest()[
        :16]
    iv = Random.new().read(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = str(phone_number) + "," + str(mobile_number) + \
        "," + str(place_of_residence)
    ciphertext = cipher.encrypt(pad(data.encode(), 16))
    message = iv + ciphertext
    calculated_mac = hmac.new(key, message, hashlib.sha256).digest()

    dataToSend = str(jsonpickle.encode(
        StructureSym(iv, calculated_mac, ciphertext)))

    request = Request("send_info", publicKey, dataToSend)
    client.send(str(jsonpickle.encode(request)).encode())
    return True


def stage3(client, session_key):
    with open("./classes/Client/public.pem", "rb") as f:
        client_public_key = f.read().decode()
    encSessionKey = pgp_c_functions.encrypt_message(
        'the_server_public_key.asc', session_key)
    request = Request("send_client_SK", client_public_key,
                      encSessionKey)
    client.send(str(jsonpickle.encode(request)).encode())
    res1 = jsonpickle.decode(client.recv(1024).decode())
    printResponse(res1.data)
    ProjectsDescriptions = ''
    ProjectsN = int(input("Enter number of projects description: "))

    for x in range(0, ProjectsN):
        projectName = input("projectName: ")
        ProjectDescriptionVal = input("ProjectDescription: ")
        ProjectsDescriptions += projectName+" "+ProjectDescriptionVal+"\n"

    # iv
    iv = Random.new().read(16)
    hashedSession = hashlib.sha256(session_key.encode()).digest()[:16]
    cipher = AES.new(hashedSession, AES.MODE_CBC, iv)
    data = ProjectsDescriptions
    ciphertext = cipher.encrypt(pad(data.encode(), 16))
    message = iv + ciphertext
    calculated_mac = hmac.new(hashedSession, message, hashlib.sha256).digest()

    struct = str(jsonpickle.encode(
        StructureSym(iv, calculated_mac, ciphertext)))
    request = Request("store_student_projects", client_public_key,
                      jsonpickle.encode(struct))
    client.send(str(jsonpickle.encode(request)).encode())
    return True


def returnServerPublic(key):
    server_public_key = key
    with open('the_server_public_key.asc', 'w') as f:
        f.write(server_public_key)
    print(colored("Server key recieved!", "white", "on_blue"))


def StoreCaPK(key):
    with open('ca_public_key.pem', 'w') as f:
        f.write(key)
    print(colored("CA Server key recieved!", "white", "on_blue"))


def sendClientPublicKey(client):
    with open("./classes/Client/public.pem", "rb") as f:
        client_public_key = f.read()
        request = Request("send_client_PK", client_public_key,
                          None)
        client.send(str(jsonpickle.encode(request)).encode())
        print(colored("Sending User Public Key...", "green"))
        return True


def printResponse(msg):
    try:
        msg = msg.decode('utf-8')
    except (UnicodeDecodeError, AttributeError):
        pass
    if "ErrorCode" in msg:
        print(colored(msg, "white", "on_red"))
    else:
        print(colored(msg, "green"))


def sendSignedMessage(client):
    filePath = input("Enter file path to send: ")
    try:
        with open("classes/Client/private.pem", 'rb') as f:
            privateKey = f.read()
        with open("classes/Client/public.pem", 'rb') as f:
            publicKey = f.read()
        sign = SignMesssage(privateKey, filePath).generate_signature()
        if sign:
            print(colored("Sending your file, please wait ...",
                  "green"))
            fileAbsPath = os.path.abspath(filePath)
            dataToSend = str(jsonpickle.encode(
                SignedMessage(publicKey.decode(), fileAbsPath, sign)))
            request = Request("verify_sig", publicKey.decode(), dataToSend)
            client.send(str(jsonpickle.encode(request)).encode())
            return True
        print(colored("Generating Failed :(", "white", "on_red"))
    except FileNotFoundError:
        print(colored("Private key not found!", "white", "on_red"))
        return False


def GenerateCRT(client, caClient):
    drName = input("Enter your university name: ")
    with open("classes/Client/public.pem", 'rb') as f:
        publicKey = f.read()
    csrPath = GenerateCSRReq(drName).generate()
    with open(csrPath, 'rb') as f:  # Convert csr to bytes to send
        csr = f.read()
    # Solve equation
    code = input("Let the following equation be:\n" +
                 "5+X = verifyCode\n" +
                 "What is the value of x? x = ")
    # send request
    dataToSend = str(jsonpickle.encode(
        csrReq(csr.decode(), code)))
    request = Request("verify_csr", publicKey.decode(), dataToSend)
    caClient.send(str(jsonpickle.encode(request)).encode())
    return True


def StoreCRT(data):
    with open("classes/Client/" + data.fileName, 'w') as file:
        file.write(data.crt)
    print(colored("CRT Generated in : " + "classes/Client/" + data.fileName, "green"))
    return True


if __name__ == "__main__":
    main()
