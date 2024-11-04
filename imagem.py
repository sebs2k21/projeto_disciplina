import cv2
import numpy as np
from stegano import lsb
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import hashlib

def embutir_texto_em_imagem(texto, caminho_imagem):
    imagem_alterada = lsb.hide(caminho_imagem, texto)
    imagem_alterada.save("imagem_alterada.png")
    print("Texto embutido com sucesso na imagem.")

def recuperar_texto_de_imagem(caminho_imagem):
    texto = lsb.reveal(caminho_imagem)
    if texto:
        print(f"Texto recuperado: {texto}")
    else:
        print("Nenhum texto encontrado na imagem.")

def gerar_hash_imagem(caminho_imagem):
    with open(caminho_imagem, "rb") as f:
        dados = f.read()
        hash_imagem = hashlib.sha256(dados).hexdigest()
    print(f"Hash da imagem ({caminho_imagem}): {hash_imagem}")
    return hash_imagem

def gerar_chaves():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica

def encriptar_mensagem(chave_publica, mensagem):
    mensagem_encriptada = chave_publica.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensagem_encriptada

def decriptar_mensagem(chave_privada, mensagem_encriptada):
    mensagem_decriptada = chave_privada.decrypt(
        mensagem_encriptada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensagem_decriptada.decode()

def menu():
    chave_privada, chave_publica = gerar_chaves()
    while True:
        print("\nMenu de Opções:")
        print("(1) Embutir texto em imagem")
        print("(2) Recuperar texto de imagem")
        print("(3) Gerar hash das imagens")
        print("(4) Encriptar mensagem com chave pública")
        print("(5) Decriptar mensagem com chave privada")
        print("(S) Sair")
        
        opcao = input("Escolha uma opção: ").strip().lower()
        
        if opcao == "1":
            texto = input("Digite o texto a ser embutido: ")
            caminho_imagem = input("Digite o caminho da imagem original: ")
            embutir_texto_em_imagem(texto, caminho_imagem)
        
        elif opcao == "2":
            caminho_imagem = input("Digite o caminho da imagem alterada: ")
            recuperar_texto_de_imagem(caminho_imagem)
        
        elif opcao == "3":
            caminho_imagem_original = input("Digite o caminho da imagem original: ")
            caminho_imagem_alterada = input("Digite o caminho da imagem alterada: ")
            hash_original = gerar_hash_imagem(caminho_imagem_original)
            hash_alterada = gerar_hash_imagem(caminho_imagem_alterada)
            if hash_original == hash_alterada:
                print("As imagens são idênticas.")
            else:
                print("As imagens foram alteradas.")
        
        elif opcao == "4":
            mensagem = input("Digite a mensagem a ser encriptada: ")
            mensagem_encriptada = encriptar_mensagem(chave_publica, mensagem)
            print("Mensagem encriptada com sucesso.")
        
        elif opcao == "5":
            mensagem_encriptada = input("Digite a mensagem encriptada em formato bytes (use b'...'): ")
            try:
                mensagem_encriptada = eval(mensagem_encriptada)  # Converter para bytes
                mensagem_decriptada = decriptar_mensagem(chave_privada, mensagem_encriptada)
                print(f"Mensagem decriptada: {mensagem_decriptada}")
            except Exception as e:
                print("Erro ao decriptar a mensagem:", e)
        
        elif opcao == "s":
            print("Saindo do programa.")
            break
        else:
            print("Opção inválida, tente novamente.")

# Executar o menu
menu()
