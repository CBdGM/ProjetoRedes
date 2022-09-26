from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
import random



def handshake(mClientSocket, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ):
    manter_conexao = True
    while manter_conexao: #while para manter a conexão com o cliente enquanto for necessário

        # Recebendo os dados do Cliente:
        data = mClientSocket.recv(2048) #recebe a primeira requisição do cliente
        req = data.decode() # a resposta é recebida em bytes, por isso é preciso transformar bytes em string para podermos entender
        
        if req == "CLIENT HELLO": #respondendo o client hello enviado pelo cliente, ele quer as chaves publicas

            req = "SERVER HELLO" # da a resposta para o cliente saber que esse é o server hello e o conteudo é as chaves publicas
            mClientSocket.send(req.encode()) #envia a requisicao

            mClientSocket.send(P_ChavePubServ.encode()) #envia as chaves publicas
            mClientSocket.send(G_ChavePubServ.encode())
            
           

        if req == "CHANGE CIPHER": # ocorre a troca do segredo compartilhado (cipher), necessário para a calcular a chave secreta
            X_cipherCliente = mClientSocket.recv(2048) # ta recebendo o segredo compartilhado do cliente
            X_cipherCliente = X_cipherCliente.decode()
            X_cipherCliente = int(X_cipherCliente) #transformando para int para poder calcular depois
            print(f"cipher cliente: {X_cipherCliente}")
                    
            G_ChavePubServ = int(G_ChavePubServ) #transformando para int para poder realizar o calculo
            P_ChavePubServ = int(P_ChavePubServ)


            Y_cipherServidor = int(pow(G_ChavePubServ, B_ChavePrivServ, P_ChavePubServ)) #calculo do cipher do servidor
            print(f"cipher servidor: {Y_cipherServidor}")   
            Y_cipherServidor = str(Y_cipherServidor) # transformando para string para poder mandar para o cliente
            mClientSocket.send(Y_cipherServidor.encode()) #mandando o cipher para o cliente

            req = "HANDSHAKE FINISHED" # notificando que a troca de informações foi concluida e que ja pode ser feito o calculo da chave secreta
            mClientSocket.send(req.encode())


        if req == "HANDSHAKE FINISHED": # recebe do cliente que ele ja fez a chave secreta e também o servidor pode fazer a chave secreta dele

            chave_secreta_servidor = int(pow(X_cipherCliente, B_ChavePrivServ, P_ChavePubServ)) # calculo da chave secreta
            print(f"chave secreta servidor: {chave_secreta_servidor}")
            manter_conexao = False 
            return chave_secreta_servidor
            

def HandleRequest(mClientSocket, mClientAddr, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ): 
    chave_secreta_servidor = handshake(mClientSocket, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ) 
    #separei em duas funções para depois se houver mais comunicações o codigo ficar mais facil de entender
    # depois da para fazer isso com o cliente também se precisar


#DADOS
HOST = "127.0.0.1"
PORT = 1235
P_ChavePubServ = "23"
G_ChavePubServ = "9"
# essa é a chave privada do servidor
# a função randint escolher um numero aleatório (1, 64) diz que esse numero vai ser entre 1 e 64
B_ChavePrivServ = random.randint(1, 64) #


#Passo 1: Criação do socket
mSocketServer = socket(AF_INET, SOCK_STREAM)
print(f'Socket criado ...')

#Passo 2: Transformando o socket em um socket servidor.
#Dar Bind significa vincular um socket a um endereço
mSocketServer.bind((HOST, PORT))
#Colocar o servidor para escutar as solicitações de conexão
mSocketServer.listen()
while True:
    # Este loop foi colocado para que o servidor conseguisse se conectar com vários cliente;
    # Passo 3: Colocar o servidor para aceitar as solicitações de conexão:
    clientSocket, clientAddr =  mSocketServer.accept()
    print(f'\nO servidor aceitou a conexão do Cliente: {clientAddr}')
    # Passo 4: Criação de múltiplas threads para que o servidor consiga responder mais de
    # um cliente por vez.
    Thread(target=HandleRequest, args=(clientSocket, clientAddr, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ)).start()
