from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from termcolor import colored, cprint
import os

# Generate a private key


class GenerateCAKeys:
    def Generate():
        if (os.path.exists("classes/CAServer/keys/ca_private_key.pem") and os.path.exists("classes/CAServer/keys/ca_public_key.pem")):
            return False
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Extract the public key from the private key
        public_key = private_key.public_key()

        # Serialize the private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if not os.path.isdir('./classes/CAServer/keys'):
            os.mkdir("classes/CAServer/keys")

        # Write the private key to a file
        with open("classes/CAServer/keys/ca_private_key.pem", "wb") as private_key_file:
            private_key_file.write(private_key_pem)

        # Write the public key to a file
        with open("classes/CAServer/keys/ca_public_key.pem", "wb") as public_key_file:
            public_key_file.write(public_key_pem)

        print(colored("Public and private keys generated.", "green"))
        return True
