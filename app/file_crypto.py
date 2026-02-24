from cryptography.fernet import Fernet
import argparse
import os

# Récupérer la clé depuis l'environnement ou en générer une nouvelle
fernet_key = os.getenv("FERNET_KEY")
if fernet_key:
    fernet = Fernet(fernet_key.encode())
else:
    # Générer une clé temporaire (pour les tests locaux uniquement)
    print("⚠️  Aucune clé FERNET_KEY définie. Génération d'une clé temporaire (non sécurisé pour la production).")
    key = Fernet.generate_key()
    fernet = Fernet(key)
    print(f"Clé générée : {key.decode()}. Exportez-la avec `export FERNET_KEY='...'` pour une utilisation future.")

def encrypt_file(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(output_path, "wb") as f:
        f.write(encrypted)
    print(f"✅ Fichier chiffré : {output_path}")

def decrypt_file(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    with open(output_path, "wb") as f:
        f.write(decrypted)
    print(f"✅ Fichier déchiffré : {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chiffrer/déchiffrer un fichier avec Fernet.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt ou decrypt")
    parser.add_argument("input", help="Fichier d'entrée")
    parser.add_argument("output", help="Fichier de sortie")
    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.input, args.output)
    else:
        decrypt_file(args.input, args.output)
