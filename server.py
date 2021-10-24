import re
import sys
import threading
import time
import hashlib
import socket
import os


import base64

from  Crypto.Cipher import AES
from Crypto import Random
secret_thing = hashlib.sha256()


HOST = "localhost"
PORT = 8083
Auth_PASS = "t6w9z$C&F)J@NcRfUjXn2r5u8x!A%D*G"
PASS_PHRASE = ""

global EXIT_Validation
global EXIT_Connections
EXIT_Validation = 0
EXIT_Connections = 0
CONNECTIONS = {}
secret_thing.update(Auth_PASS.encode())
ENC_Auth = secret_thing.hexdigest()
Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

Socket.bind((HOST, PORT))
Socket.listen()


class bcolors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[31m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BGRED = '\033[41m'
    WHITE = '\033[37m'


def t():
    current_time = time.localtime()
    ctime = time.strftime('%H:%M:%S', current_time)
    return '[' + ctime + ']'


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


def ShowClients():
    NUM = 0
    if len(CONNECTIONS) != 0:
        for client in CONNECTIONS:
            NUM += 1
            address = client[0]
            port = client[1]
            print(bcolors.YELLOW + bcolors.BOLD)
            print(f"{NUM}) IP: {address} PORT: {port}")
    else:
        print(bcolors.ENDC + bcolors.BOLD)
        print("[-] Tidak Ada CLient Tersedia!")


def MessageClient(IP, PORT, Message):
    if len(CONNECTIONS) != 0:
        ENC_AES = AES_HASH.encrypt(Message)
        for client in CONNECTIONS:
            Ipaddress = client[0]
            IpPort = client[1]
            CONN = CONNECTIONS[client]
            if IP.strip() == Ipaddress and PORT.strip() == str(IpPort):
                CONN.send(ENC_AES)
                print(bcolors.GREEN + bcolors.BOLD)
                print("[+] Message Sent...")
    else:
        print(bcolors.WHITE + bcolors.BOLD)
        print("[-] No Client Available!")


def MessageAll(Message):
    ENC_AES = AES_HASH.encrypt(Message)
    for client in CONNECTIONS:
        CONNECTIONS[client].send(ENC_AES)
    print(bcolors.GREEN + bcolors.BOLD)
    print("[+] Pesan Terkirim Ke semua Client...")


def Validate_Connections():
    global EXIT_Validation
    DISCONNECTED = []
    KEEP_ALIVE = "KEEPALIVE"
    KEEP_ALIVE = AES_HASH.encrypt(KEEP_ALIVE)
    while EXIT_Validation != 1:
        time.sleep(1)
        for Client in CONNECTIONS:
            try:
                if EXIT_Validation != 1:
                    CONNECTIONS[Client].send(KEEP_ALIVE)
                else:
                    break
            except:
                DISCONNECTED.append(Client)
        for Client in DISCONNECTED:
            del CONNECTIONS[Client]
        DISCONNECTED.clear()
    print("Braked Validating")


def Connections():
    global EXIT_Connections
    Socket.settimeout(5)
    Welcome = "Welcome".encode()
    while EXIT_Connections != 1:
        try:
            conn, addr = Socket.accept()
            if conn:
                conn.send(b"Pass: ")
                PASS = conn.recv(1024)
                if PASS.decode() == ENC_Auth:
                    # When Auth Completed #
                    CONNECTIONS[addr] = conn
                    print(bcolors.BLUE + bcolors.BOLD)
                    print(f"\n{t()} new connection from {addr} Connection: {len(CONNECTIONS)}")
                    conn.send(Welcome)
                else:
                    conn.close()
        except:
            pass
    print("Koneksi Rusak")


def Selector():
    global EXIT_Validation
    global EXIT_Connections
    while True:
        print(bcolors.RED + bcolors.BOLD)
        options = """
       Program Encrypty dan Decrypty
       1. Tampilkan Clients         
       2. Kirim Pesan <Client IP>   
       3. Kirim Pesan Kesemua       
       4. Exit                      
   
        \n>"""
        try:
            OP = input(options)
            clear()
            if OP == "1":
                ShowClients()
            elif OP == "2":
                if len(CONNECTIONS) != 0:
                    ShowClients()
                    print()
                    IP = input("IP: ")
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", IP):
                        PORT = input("PORT: ")
                        if re.match(
                                r"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$",
                                PORT):
                            Message = input("Pesan: ")
                            MessageClient(IP=IP, PORT=PORT, Message=Message)
                        else:
                            print(bcolors.FAIL + bcolors.BOLD)
                            print("Port Salah!")
                    else:
                        print(bcolors.FAIL + bcolors.BOLD)
                        print("IP Addres Salah!")
                else:
                    print(bcolors.WHITE + bcolors.BOLD)
                    print("[-] Tidak Ada Client!")

            elif OP == "3":
                if len(CONNECTIONS) != 0:
                    Message = input("Message: ")
                    MessageAll(Message)
                else:
                    print(bcolors.WHITE + bcolors.BOLD)
                    print("[-] Tidak Ada Client!")
            elif OP == "4":
                clear()
                EXIT_Validation = 1
                time.sleep(0.5)
                EXIT_Connections = 1
                print("Tunggu 5 Second Untuk Close Semuat Thread")
                time.sleep(5)
                input("Tekan Enter Untuk Keluar..")
                clear()
                sys.exit()
            elif OP == "clear" or OP == "cls":
                clear()
            else:
                print(bcolors.FAIL + bcolors.BOLD)
                input("\n[-] Pilihan Salah!")
        except KeyboardInterrupt:
            clear()
            EXIT_Validation = 1
            time.sleep(0.5)
            EXIT_Connections = 1
            print("Tunggu 5 Second Untuk Keluar")
            time.sleep(5)
            input("Tekan Enter Untuk Keluar...")
            clear()
            sys.exit()


if __name__ == "__main__":
    clear()
    AES_HASH = AESCipher(PASS_PHRASE)
    Conn = threading.Thread(target=Connections)
    Validate = threading.Thread(target=Validate_Connections)
    Conn.start()
    Validate.start()

    Selector()
