from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
import random
import cryptocode


def Handshake(mClientSocket, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ):

    while True: #while para manter a conexão com o cliente enquanto for necessário

        # Recebendo os dados do Cliente:
        data = mClientSocket.recv(2048) #recebe a primeira requisição do cliente
        req = data.decode() # a resposta é recebida em bytes, por isso é preciso transformar bytes em string para podermos entender


        if req == "CLIENT HELLO": #respondendo o client hello enviado pelo cliente, ele quer as chaves publicas

            resp = "SERVER HELLO" # da a resposta para o cliente saber que esse é o server hello e o conteudo é as chaves publicas
            mClientSocket.send(resp.encode()) #envia a requisicao

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

            resp = "HANDSHAKE FINISHED" # notificando que a troca de informações foi concluida e que ja pode ser feito o calculo da chave secreta
            mClientSocket.send(resp.encode())


        if req == "HANDSHAKE FINISHED": # recebe do cliente que ele ja fez a chave secreta e também o servidor pode fazer a chave secreta dele

            chave_secreta_servidor = int(pow(X_cipherCliente, B_ChavePrivServ, P_ChavePubServ)) # calculo da chave secreta
    
            #o return ja acaba com a função e retorna a chave secreta
            # a variável manter_conexão no while não precisa por causa desse return
            # a chave secreta é transformada em string por causa da função de criptografia que exige ela em string para criptografar 
            return str(chave_secreta_servidor) 

            

def GetHandler(mClientSocket, chave_secreta_servidor): # essa função lida com as requisições do get

    dados = mClientSocket.recv(2048)  #atende a requisição do cliente
    dados = dados.decode() #decodificado de bytes para string
    dados = cryptocode.decrypt(dados, chave_secreta_servidor) # decriptografado utilziando a chave secreta
    print(f'requisição do cliente: {dados}')

    #resposta a solicitação 
    cabecalho = 'HTTP/1.1 200 OK \r\n' \
                'Date: Tue, 09 Aug 2022 13:23:35 GMT\r\n' \
                'Server: MyServer/0.0.1 (Ubuntu)\r\n' \
                'Content-Type: text/html\r\n' \
                '\r\n'

    payload = '<html>' \
              '<head><title>Projeto de redes</title></head>' \
              '<body><h1> Projeto de redes</h1>' \
              '<h2>Teste Teste Teste</h2>' \
              '</body>' \
              '</html>'

    # a resposta dessa requisição é um arquivo (txt) com conteudo html consistindo em um cabeçalho e a carga util
    MensagemRespostahtml = cabecalho + payload

    #para ser implementado
    #codigo 200
    #MensagemRespostahtml =  MensagemRespostahtml.sucesso()
    #codigo 404
    #MensagemRespostahtml = MensagemRespostahtml.NaoEncontrado()
    

    MensagemRespostahtml = cryptocode.encrypt(MensagemRespostahtml, chave_secreta_servidor) #criptografa a mensagem
    mClientSocket.send(MensagemRespostahtml.encode())


def HandleRequest(mClientSocket, mClientAddr, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ): 

    # Inicialmente é preciso realizar o handshake com o cliente para calcular a chave de criptografia
    chave_secreta_servidor = Handshake(mClientSocket, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ)
    print(f"chave secreta servidor: {chave_secreta_servidor}")
    
    # A próxima etapa consiste em atender as requisições do cliente que nesse caso é o get
    GetHandler(mClientSocket, chave_secreta_servidor)
    


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
