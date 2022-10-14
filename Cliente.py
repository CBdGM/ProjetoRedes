from socket import socket, AF_INET, SOCK_STREAM
import random
import cryptocode


def Handshake(mClientSocket, A_ChavePrivClient):

    req = None
    mensagem = "CLIENT HELLO" # ta fazendo a primeira requisição pro servidor
    mClientSocket.send(mensagem.encode()) #Ta notificando pro servidor que esse é o client hello, ou seja, ta pedindo as chaves publicas

    while True: 

        req = mClientSocket.recv(2048)
        req = req.decode() #recebe a resposta do servidor, se tudo der certo tem que receber o server hello

        if req == "SERVER HELLO":
            P_ChavePubServ = mClientSocket.recv(2048)#recebendo as duas chaves publicas
            G_ChavePubServ = mClientSocket.recv(2048)

            P_ChavePubServ = int(P_ChavePubServ.decode()) #decodificando para int para poder calcular depois
            G_ChavePubServ = int(G_ChavePubServ.decode()) #decodificando para int
           

            # cipher é um numero pré criptografia que utliza as chaves publicas e privadas para fazer um segredo que vai ser compartilhado entre o cliente e servidor
            # vai ser usado como parametro para calcular a chave secreta
            # tambem é chamado de chave modular
            X_cipherCliente = int(pow(G_ChavePubServ, A_ChavePrivClient, P_ChavePubServ)) 


            #transformando para string para mandar para o servidor
            # a função encode só aceita string como parametro para codificar
            # por isso tou transformando em string antes de mandar
            X_cipherCliente = str(X_cipherCliente) 

            mensagem = "CHANGE CIPHER" #cabeçalho para o servidor entender o que ta acontecendo (troca dos segredos compartilhados)
            mClientSocket.send(mensagem.encode())
            mClientSocket.send(X_cipherCliente.encode()) #mandando o cipher

            Y_cipherServidor = mClientSocket.recv(2048) #recebendo o cipher
            Y_cipherServidor = int(Y_cipherServidor.decode()) #decodificando direto pra inteiro para poder calcular dps
        


        if req == "HANDSHAKE FINISHED":
            chave_secreta_cliente = int(pow(Y_cipherServidor, A_ChavePrivClient, P_ChavePubServ)) #calculo da chave secreta
            print(f"Chave secreta cliente: {chave_secreta_cliente}\n")
            mClientSocket.send(req.encode()) #alertanado para o servidor que ja possui a chave secreta
            return str(chave_secreta_cliente)

#função que lida com as requisições get
def GET(mClientSocket, req):

    req = cryptocode.encrypt(req, chave_secreta_cliente) #criptografia da requisição
    req = req.encode()
    mClientSocket.send(req) # envio da requisição

    dados = mClientSocket.recv(2048) # recebimento dos dados respondidos pelo servidor após a requisição
    dados = dados.decode()
    dados = cryptocode.decrypt(dados, chave_secreta_cliente) # descriptografia
    print(dados)

# função que comunica com o servidor sobre o indetificador
def AcharIndentificador(mClientSocket, indentificador = "None"):
    mClientSocket.send(indentificador.encode()) # envia o indentificador que possui ("None" para não possuir nenhum id)
    resp = mClientSocket.recv(2048) # recebe a resposta do servidor sobre o status do indentificador
    resp = resp.decode()
    print(resp)
    if resp != "ID OK": # se o indentificador não existir ou não for encontrado é criado um novo indentificador e o cliente salva ele
        indentificador = mClientSocket.recv(2048) # recebe o novo indentificador
        indentificador = indentificador.decode()
        print(indentificador)

#DADOS

# essa é a chave privada do cliente
# a função randint escolher um numero aleatório. (1, 64) diz que esse numero vai ser entre 1 e 64
# eu so escolhi qualquer numero para ser o 64, podia ser qualquer um (acho)
A_ChavePrivClient = random.randint(1, 64)
chave_secreta_cliente = None

indentificador = "None"


mClientSocket = socket(AF_INET, SOCK_STREAM) #criando o socket
mClientSocket.connect(('127.0.0.1', 1235)) #se conectando com o servidor


# a primeira comunicação é para ver se o cliente ja se comunicou com o servidor antes e ser indentificado no servidor
AcharIndentificador(mClientSocket, indentificador) 


# é necessário fazer o primeiro contato com o servidor para garantir a criptografia
# a função handshake é responsavel por calcular a chave de criptografia utilizada para a troca de mensagens
chave_secreta_cliente = Handshake(mClientSocket, A_ChavePrivClient)

# essa é a primeira requisição feita para o servidor
# apenas um get de teste que recebe uma string com conteudo html
req = "teste"
GET(mClientSocket, req)
