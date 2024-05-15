import sqlite3
import jsonpickle
from datetime import datetime
import socket
from Crypto.Util.Padding import pad, unpad
from classes.Server.Models.Response import Response
from classes.Server.Models.Request import Request
from classes.CAServer.Models.CsrReq import csrReq
from classes.CAServer.Models.CRTRes import crtRes
from classes.CAServer.GenerateCAKeys import GenerateCAKeys
from classes.CAServer.VerifyCSR import VerifyCSR
from classes.CAServer.GenerateCert import generateCRT
from classes.Helpers.auth import auth
import threading
import hmac
import classes.Server.Stage3.pgp_s_functions as pgp_s_functions
from termcolor import colored, cprint

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = "localhost"
port = 9998
server.bind((ip, port))
server.listen()
GenerateCAKeys.Generate()
print()
print(colored("Starting server at >> " + str(ip) + ":" + str(port), "green"))
print()


def handle_connection(c):
    while True:
        option = c.recv(2048).decode()
        request = jsonpickle.decode(option)
        print(colored("Request resived at : " +
              datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "green"))
        ###
        match request.url:
            case "get_PK":
                data = getCAPK(c)
                response = Response("return_server_public", data)
            case "verify_csr":
                data = handle_csr_verification(
                    c, request.public_key, request.data)
                response = Response("return_crt", jsonpickle.encode(data))
            case _:
                response = Response("print", "Route not found! ErrorCode 404")
                print(colored("Route Not Found!", "red"))
        print(colored("Response returned at : " +
                      datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "green"))
        c.send(str(jsonpickle.encode(response)).encode())


def getCAPK(c):
    with open("classes/CAServer/keys/ca_public_key.pem", "rb") as f:
        ca_server_public_key = f.read()
    return ca_server_public_key.decode()


def handle_csr_verification(c, pk, data):
    data = jsonpickle.decode(data)
    if not VerifyCSR(pk, data.csr, data.code):
        return "CSR signature is invalid."
    crt = generateCRT(pk, data.csr).generate()
    print(colored("A new CRT Generated at " +
          str(datetime.now()), "white", "on_blue"))
    with open("classes/CAServer/CRT_Files/" + crt, 'r') as file:
        crtKey = file.read()
    crtObj = crtRes(crt, crtKey)
    return crtObj


while True:
    client, addr = server.accept()
    threading.Thread(target=handle_connection, args=(client,)).start()
