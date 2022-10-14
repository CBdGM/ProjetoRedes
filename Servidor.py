from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
import random
import cryptocode
from DadosCliente import Cliente
import pickle
from uuid import uuid1

# Essa função faz o handshake para obter a chave de criptografia
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
                    
            G_ChavePubServ = int(G_ChavePubServ) #transformando para int para poder realizar o calculo
            P_ChavePubServ = int(P_ChavePubServ)


            Y_cipherServidor = int(pow(G_ChavePubServ, B_ChavePrivServ, P_ChavePubServ)) #calculo do cipher do servidor  
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


# Essa função é uma thread que lida com a comunicação via sockets de cada cliente
def HandleRequest(mClientSocket, mClientAddr, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ, banco_de_dados):

    #inicialmente vamos ver se o cliente ja se comunicou antes com o servidor atraves de um indentificador unico
    #se ele não possuir um indentificador ou não for achado um novo vai ser criado para ele
    c1 = Acharindentificador(mClientSocket, banco_de_dados, mClientAddr)
    # essa função retorna c1, que é a estrutura de dados do cliente contendo informações sobre ele
    # aqui por exemplo foi printado o endereço apenas para testar
    print(c1.endereço)

    # em seguida é feito o handshake para adquirir a chave secreta
    chave_secreta_servidor = Handshake(mClientSocket, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ)
    print(f"chave secreta servidor: {chave_secreta_servidor}")
    
    # A próxima etapa consiste em atender as requisições do cliente que nesse caso é o get
    GetHandler(mClientSocket, chave_secreta_servidor)


# essa função carrega o banco de dados do arquivo txt para o código
def CarregarBancoDeDados():
    # o banco de dados consistem em um dicionário onde o indentificador unico é a chave e a estrutura de dados do cliente é o conteudo
    banco_de_dados = {}
    # é utilizado uma exceção para erro caso o banco de dados esteja vazio, dessa forma o código continua e podemos preencher ele
    try: 
        arquivo = open("banco_de_dados.txt", "rb") # abre o arquivo de texto
        banco_de_dados = pickle.load(arquivo) #utiliza a biblioteca pickle para pegar o conteúdo do arquivo
        arquivo.close() # fecha o arquivo
    except EOFError:
        print("banco de dados vazio")
    
    return banco_de_dados # retorna no código o banco de dados em formato de dicionário

# essa função serve para atualizar o banco de dados
def SalvarBancoDeDados(banco_de_dados): 
    arquivo = open("banco_de_dados.txt", "wb") # abre o arquivo
    pickle.dump(banco_de_dados, arquivo) # a função dump do pickle salva o dicionário banco de dados no arquivo
    arquivo.close() # fecha o arquivo


# essa funãço é responsável por descobrir se o cliente possui um indentificador único e lidar com isso caso ele não tenha
def Acharindentificador(mClientSocket, banco_de_dados, mClientAddr):

    indentificador = mClientSocket.recv(2048) # recebe do cliente um indentificador ou "None" caso não tenha indentificador
    indentificador = indentificador.decode()

    if indentificador != "None": #se existir indentificador (indentificador não for None) procurar no banco de dados 
        # tratamento de erro para caso ele não esteja no banco de dados 
        try:
            c1 = banco_de_dados[indentificador] #testa para ver se ta no banco de dados
            resp = "ID OK" # se tiver responde para o cliente dizendo que o indentificador esta ok
            mClientSocket.send(resp.encode())
        except KeyError: # se der erro (o indentificador não estiver no banco de dados) comunicar o cliente e criar um novo
            print("cliente não encontrado")
            resp = "NOT FOUND"
            mClientSocket.send(resp.encode())
            indentificador, c1 = NovoIndentificador(banco_de_dados, mClientAddr)
            mClientSocket.send(indentificador.encode())

    # se não existir indentificador criar um e enviar para o cliente
    else:
        indentificador, c1 = NovoIndentificador(banco_de_dados, mClientAddr)
        resp = "NEW ID"
        mClientSocket.send(resp.encode())
        mClientSocket.send(indentificador.encode())

    return c1 # retorna a estrutura de dados cliente para o código

# essa função é reponsável por criar um novo indentificador e salvar como novo cliente no banco de dados
def NovoIndentificador(banco_de_dados, mClientAddr):
    # é utilizado a função uuid1 da biblioteca uuid para criar um conjunto de caracteres que vão servir
    # para como indentificador único do cliente
    indentificador = uuid1() 
     # a biblioteca cria o identificador numa estrutura de dados dela e a gente passa para string para melhor manipulação
    indentificador = str(indentificador)
    print(f"indentificador unico: {indentificador}")

    # criação da estrutura de dados cliente
    c1 = Cliente(indentificador, mClientAddr) # é passado como parametro o indentificador e o endenreço do seu acesso
    banco_de_dados[indentificador] = c1 # salvando no banco de dados o cliente com o seu id

    return indentificador, c1 # retornamos o id e o cliente



# COMEÇO DO CÓDIGO

#DADOS
HOST = "127.0.0.1"
PORT = 1235
P_ChavePubServ = "23"
G_ChavePubServ = "9"
# essa é a chave privada do servidor
# a função randint escolher um numero aleatório (1, 64) diz que esse numero vai ser entre 1 e 64
B_ChavePrivServ = random.randint(1, 64) 



# primeiramente recuperamos do arquivo o banco de dados para ser utilizado no código
banco_de_dados = CarregarBancoDeDados()
print(banco_de_dados)



# Criação do socket
mSocketServer = socket(AF_INET, SOCK_STREAM)
print(f'Socket criado ...')

#Transformando o socket em um socket servidor.
# Dar Bind significa vincular um socket a um endereço
mSocketServer.bind((HOST, PORT))
#Colocar o servidor para escutar as solicitações de conexão
mSocketServer.listen()
while True:
    # Este loop foi colocado para que o servidor conseguisse se conectar com vários cliente;
    # Passo 3: Colocar o servidor para aceitar as solicitações de conexão:
    clientSocket, clientAddr =  mSocketServer.accept()
    print(f'\nO servidor aceitou a conexão do Cliente: {clientAddr}')


    # Criação de múltiplas threads para que o servidor consiga responder mais de um cliente por vez.
    Thread(target=HandleRequest, args=(clientSocket, clientAddr, P_ChavePubServ, G_ChavePubServ, B_ChavePrivServ, banco_de_dados)).start()

    # salvando (ou atualizando) e printando o banco de dados
    SalvarBancoDeDados(banco_de_dados)
    print(banco_de_dados)
    print("\n")
