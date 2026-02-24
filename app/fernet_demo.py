from cryptography.fernet import Fernet

# Générer une clé Fernet (256 bits, encodée en Base64)
key = Fernet.generate_key()
fernet = Fernet(key)

def encrypt_message(message: str) -> bytes:
    return fernet.encrypt(message.encode())

def decrypt_message(token: bytes) -> str:
    return fernet.decrypt(token).decode()

if __name__ == "__main__":
    message = "Mon message secret"
    print(f"Clé Fernet : {key.decode()}")
    print(f"Texte original : {message}")

    token = encrypt_message(message)
    print(f"Texte chiffré : {token.decode()}")

    decrypted = decrypt_message(token)
    print(f"Texte déchiffré : {decrypted}")
