from nacl.secret import SecretBox
from nacl.encoding import Base64Encoder
import os
import argparse

def get_secretbox_key():
    """Génère ou récupère une clé pour SecretBox."""
    # Récupérer la clé depuis l'environnement (optionnel)
    key_b64 = os.getenv("SECRETBOX_KEY")
    if key_b64:
        key = Base64Encoder.decode(key_b64.encode())
    else:
        # Générer une nouvelle clé si aucune n'est définie
        key = SecretBox.generate_key()
        print(f"Aucune clé SECRETBOX_KEY définie. Nouvelle clé générée : {Base64Encoder.encode(key).decode()}")
    return SecretBox(key)

def encrypt_file(input_path: str, output_path: str):
    """Chiffre un fichier avec SecretBox."""
    box = get_secretbox_key()
    with open(input_path, "rb") as f:
        data = f.read()
    encrypted = box.encrypt(data, encoder=Base64Encoder)
    with open(output_path, "w") as f:
        f.write(encrypted.decode())
    print(f"Fichier chiffré : {output_path}")

def decrypt_file(input_path: str, output_path: str):
    """Déchiffre un fichier avec SecretBox."""
    box = get_secretbox_key()
    with open(input_path, "r") as f:
        encrypted = f.read().encode()
    decrypted = box.decrypt(encrypted, encoder=Base64Encoder)
    with open(output_path, "wb") as f:
        f.write(decrypted)
    print(f"Fichier déchiffré : {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chiffrer/déchiffrer un fichier avec PyNaCl SecretBox.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt ou decrypt")
    parser.add_argument("input", help="Fichier d'entrée")
    parser.add_argument("output", help="Fichier de sortie")
    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.input, args.output)
    else:
        decrypt_file(args.input, args.output)
