
from cryptography.fernet import Fernet
import os
import argparse

def get_fernet_key():
    """Récupère la clé Fernet depuis les secrets GitHub ou l'environnement."""
    fernet_key = os.getenv("FERNET_KEY")
    if not fernet_key:
        raise ValueError(
            "La clé FERNET_KEY n'est pas définie. "
            "Définissez-la dans les secrets GitHub ou via `export FERNET_KEY='...'`"
        )
    return Fernet(fernet_key.encode())

def encrypt_file(input_path: str, output_path: str):
    """Chiffre un fichier avec Fernet."""
    fernet = get_fernet_key()
    with open(input_path, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(output_path, "wb") as f:
        f.write(encrypted)
    print(f" Fichier chiffré : {output_path}")

def decrypt_file(input_path: str, output_path: str):
    """Déchiffre un fichier avec Fernet."""
    fernet = get_fernet_key()
    with open(input_path, "rb") as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    with open(output_path, "wb") as f:
        f.write(decrypted)
    print(f"Fichier déchiffré : {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chiffrer/déchiffrer un fichier avec Fernet (clé dans GitHub Secrets).")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt ou decrypt")
    parser.add_argument("input", help="Fichier d'entrée")
    parser.add_argument("output", help="Fichier de sortie")
    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.input, args.output)
    else:
        decrypt_file(args.input, args.output)
