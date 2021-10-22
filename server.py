from cryptography.fernet import Fernet
import socket
import threading
import pickle

class Server:
    host = socket.gethostname()
    port = 59000

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    clients = []
    nama = []
    pasword=[]
obj=Server()

def siaran(message, currentClient):
    pickle_in=open("Serialize","rb")

    example_dict=pickle.load(pickle_in)
    example_dict=message
    file2 = open("data/riwayat.txt", "a")
    file2.write(str(example_dict) + "\n")
    for client in obj.clients:
       if(client != currentClient):
           client.send(example_dict)
    file2.close()

def mengurus_client(client):
    while True:
        try:

            message = client.recv(5024)
            siaran(message, client)
            print(message)
            pickle_out = open("Serialize", "wb")
            pickle.dump(message, pickle_out)
            pickle_out.close()
        except:

            index = obj.clients.index(client)
            obj.clients.remove(client)
            client.close()

            alias = obj.nama[index]
            alias2=obj.pasword[index]
            keluar= (f'{alias} telah meninggalkan chat'.encode())
            siaran(keluar, 0)
            obj.nama.remove(alias)
            break

def menerima():
    while True:
        print('Server telah dimulai dan berjalan')
        client, address = obj.server.accept()
        print('tersambung dengan: '+str(address))
        client.send('nama?'.encode())
        isi_nama = client.recv(1024)
        obj.nama.append(isi_nama)
        obj.clients.append(client)


        message = (f'{isi_nama} telah terhubung'.encode())
        print(message)
        siaran(f'{isi_nama} telah terhubung ke chat room'.encode(),0)
        pickle_out=open("Serialize","wb")
        pickle.dump(message,pickle_out)
        pickle_out.close()
        thread = threading.Thread(target = mengurus_client, args=(client, ))
        thread.start()

menerima()