from cryptography.fernet import Fernet
import threading
import socket
import pickle



class Client:
    nama = input(str('masukkan username'))
    pw = input(str('masukkan pasword'))
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encMessage2 = fernet.encrypt(nama.encode())
    encMessage = fernet.encrypt(pw.encode())
    #pickle_out=open("Serialize","wb")
    #pickle.dump(nama,pickle_out)
    #pickle.dump(pw, pickle_out)

    #pickle_out.close()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 59000
    client.connect((host, port))
obj=Client()

def clien_menerima():
    while True:
        try:
            message = obj.client.recv(5024).decode('utf-8')
            if message == 'nama?' and 'pw?':
                obj.client.send(obj.nama.encode('utf-8'))
                obj.client.send(encMessage.encode('utf-8'))
            else:
                print(message)
                pickle_out = message
                pickle_out = open("Serialize","wb")
                example_dict = pickle.load((pickle_in))
                pickle.dump(message,pickle_out)
                pickle_out.close()
        except:
            print('username diencrypsi :', obj.encMessage2)
            print('pw diencrypsi :',obj.encMessage)
            obj.client.close()
            break



def client_mengirim():
    while True:

        menginput=input("")
        message = f'{obj.nama}:{menginput}'
        #pickle_out=open("Serialize","wb")
        #pickle.dump(message,pickle_out)
        obj.client.send(message.encode())
        #pickle_out.close()
def THREAD():
    receive_Thread = threading.Thread(target = clien_menerima)
    receive_Thread.start()

    send_Thread = threading.Thread(target=client_mengirim)
    send_Thread.start()

THREAD()