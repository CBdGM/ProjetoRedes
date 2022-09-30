from socket import socket, AF_INET, SOCK_STREAM
import random


def Handshake(mClientSocket, A_ChavePrivClient):

    manter_conexao = True
    req = None

    mensagem = "CLIENT HELLO" # ta fazendo a primeira requisição pro servidor
    mClientSocket.send(mensagem.encode()) #Ta notificando pro servidor que esse é o client hello, ou seja, ta pedindo as chaves publicas

    while manter_conexao: 

        req = mClientSocket.recv(2048)
        req = req.decode() #recebe a resposta do servidor, se tudo der certo tem que receber o server hello

        if req == "SERVER HELLO":
            P_ChavePubServ = mClientSocket.recv(2048)#recebendo as duas chaves publicas
            G_ChavePubServ = mClientSocket.recv(2048)

            P_ChavePubServ = int(P_ChavePubServ.decode()) #decodificando para int para poder calcular depois
            print(f"chave publica P: {P_ChavePubServ}")

            G_ChavePubServ = int(G_ChavePubServ.decode()) #decodificando para int
            print(f"chave publica G: {G_ChavePubServ}")


            # cipher é um numero pré criptografia que utliza as chaves publicas e privadas para fazer um segredo que vai ser compartilhado entre o cliente e servidor
            # vai ser usado como parametro para calcular a chave secreta
            # tambem é chamado de chave modular
            X_cipherCliente = int(pow(G_ChavePubServ, A_ChavePrivClient, P_ChavePubServ)) 
            
            print(f"cipher cliente: {X_cipherCliente}") #cipher é o nome em ingles para o segredo compartilhado (acho)

            #transformando para string para mandar para o servidor
            # a função encode só aceita string como parametro para codificar
            # por isso tou transformando em string antes de mandar
            X_cipherCliente = str(X_cipherCliente) 

            mensagem = "CHANGE CIPHER" #cabeçalho para o servidor entender o que ta acontecendo (troca dos segredos compartilhados)
            mClientSocket.send(mensagem.encode())
            mClientSocket.send(X_cipherCliente.encode()) #mandando o cipher

            Y_cipherServidor = mClientSocket.recv(2048) #recebendo o cipher
            Y_cipherServidor = int(Y_cipherServidor.decode()) #decodificando direto pra inteiro para poder calcular dps
            print(f"cipher servidor: {Y_cipherServidor}")
        

        if req == "HANDSHAKE FINISHED":
            chave_secreta_cliente = int(pow(Y_cipherServidor, A_ChavePrivClient, P_ChavePubServ)) #calculo da chave secreta
            print(f"Chave secreta cliente: {chave_secreta_cliente}\n")

            mClientSocket.send(req.encode()) #alertanado para o servidor que ja possui a chave secreta
            manter_conexao = False #finalizamos o handshake e ja temos a chave secreta que vai ser usada na criptografia
            return chave_secreta_cliente


#DADOS

# essa é a chave privada do cliente
# a função randint escolher um numero aleatório. (1, 64) diz que esse numero vai ser entre 1 e 64
# eu so escolhi qualquer numero para ser o 64, podia ser qualquer um (acho)
A_ChavePrivClient = random.randint(1, 64) 



mClientSocket = socket(AF_INET, SOCK_STREAM) #criando o socket
mClientSocket.connect(('127.0.0.1', 1235)) #se conectando com o servidor

# é necessário fazer o primeiro contato com o servidor para garantir a criptografia
# a função handshake é responsavel por calcular a chave de criptografia utilizada para a troca de mensagens
chave_secreta_cliente = Handshake(mClientSocket, A_ChavePrivClient)

# essa é a primeira requisição feita para o servidor
# apenas um get de teste que recebe uma string com conteudo html
req = "GET teste"
mClientSocket.send(req.encode())

dados = mClientSocket.recv(2048)
print(dados.decode())
