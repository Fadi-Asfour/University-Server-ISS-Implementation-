import os
import rsa


def generate_keys(key_size):
    # join the current folder path and the file name
    file_path = os.path.join(os.getcwd() + '/classes/Client', 'public.pem')
    if os.path.isfile(file_path):
        print("")
        print("File client_public_key found")
        return False
    else:
        public_key, private_key = rsa.newkeys(key_size)
        if not os.path.isdir('./classes/Client'):
            os.mkdir("./classes/Client")
        sigFileName = "classes/Client/" + "public.pem"
        with open(sigFileName, 'wb') as file:
            file.write(public_key.save_pkcs1("PEM"))
        sigFileName = "classes/Client/" + "private.pem"
        with open(sigFileName, 'wb') as file:
            file.write(private_key.save_pkcs1("PEM"))
        return public_key, private_key
