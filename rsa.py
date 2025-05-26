from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def gerar_chaves_rsa():
    chave_priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    chave_pub = chave_priv.public_key()
    return chave_priv, chave_pub

def codificar_mensagem(chave_pub, texto_plano):
    try:
        texto_bytes = texto_plano.encode('utf-8')
        texto_cifrado = chave_pub.encrypt(
            texto_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return texto_cifrado
    except Exception:
        return None

def decodificar_mensagem(chave_priv, texto_cifrado):
    try:
        texto_decifrado_bytes = chave_priv.decrypt(
            texto_cifrado,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return texto_decifrado_bytes.decode('utf-8')
    except Exception:
        return None

if __name__ == "__main__":
    print("\nCRIPTOGRAFIA RSA")
    priv_key, pub_key = gerar_chaves_rsa()

    if priv_key and pub_key:
        msg_original = input("Digite sua mensagem: ").strip()

        if msg_original:
            msg_codificada = codificar_mensagem(pub_key, msg_original)

            if msg_codificada:
                print(f"\nMensagem Codificada (em bytes): {msg_codificada}")
                
                msg_decodificada = decodificar_mensagem(priv_key, msg_codificada)
                
                if msg_decodificada:
                    print(f"\nMensagem Decodificada: {msg_decodificada}")
                else:
                    print("Falha ao decodificar.")
            else:
                print("Falha ao codificar.")
        else:
            print("Mensagem não pode ser vazia.")
    else:
        print("Erro ao gerar as chaves RSA.")
