from cryptography.fernet import Fernet
import argparse
import os

# Générer ou charger une clé (ici, on la génère à chaque exécution pour simplifier)
key = Fernet.generate_key()
fernet = Fernet(key)

def encrypt_file(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(output_path, "wb") as f:
        f.write(encrypted)

def decrypt_file(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    with open(output_path, "wb") as f:
        f.write(decrypted)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chiffrer/déchiffrer un fichier avec Fernet.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt ou decrypt")
    parser.add_argument("input", help="Fichier d'entrée")
    parser.add_argument("output", help="Fichier de sortie")
    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.input, args.output)
        print(f"Fichier chiffré : {args.output}")
    else:
        decrypt_file(args.input, args.output)
        print(f"Fichier déchiffré : {args.output}")
