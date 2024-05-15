import gnupg
import os


def generate_key(key_type, key_length, name_email, passphrase=None):
    current_folder = os.getcwd()

    # join the current folder path and the file name
    file_path = os.path.join(current_folder, 'server_public_key.asc')
    if os.path.isfile(file_path):
        print("File server_public_key found")
    else:
        gpg = gnupg.GPG(gnupghome="C:\\Users\\User 2004\\AppData\\Roaming\\gnupg",
                        gpgbinary="C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe")
        input_data = gpg.gen_key_input(
            key_type=key_type,
            key_length=key_length,
            name_email=name_email,
            passphrase=passphrase
        )
        key = gpg.gen_key(input_data)

        ascii_armored_public_keys = gpg.export_keys(key.fingerprint)
        ascii_armored_private_keys = gpg.export_keys(
            keyids=key.fingerprint,
            secret=True,
            passphrase=passphrase,
        )

        # with open(f'{key.fingerprint}.asc', 'w') as f:
        #     f.write(ascii_armored_public_keys)
        #     f.write(ascii_armored_private_keys)
        with open(f'server_public_key.asc', 'w') as f:
            f.write(ascii_armored_public_keys)
        with open(f'server_private_key.asc', 'w') as f:
            f.write(ascii_armored_private_keys)

        return key.fingerprint


def encrypt_message(key_file, message):
    gpg = gnupg.GPG(gnupghome="C:\\Users\\User 2004\\AppData\\Roaming\\gnupg",
                    gpgbinary="C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe")
    # read the key data from the file
    key_data = open(key_file).read()
    # import the key to the keyring
    import_result = gpg.import_keys(key_data)
    # get the first fingerprint from the import result
    fingerprint = import_result.fingerprints[0]
    # encrypt the message for the recipient
    encrypted_data = gpg.encrypt(
        message, recipients=[fingerprint], always_trust=True)
    # return the encrypted data as a string
    return str(encrypted_data)
###################


def decrypt_message(encrypted_data, passphrase):
    gpg = gnupg.GPG(gnupghome="C:\\Users\\User 2004\\AppData\\Roaming\\gnupg",
                    gpgbinary="C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe")
    decrypted_data = gpg.decrypt(
        encrypted_data,
        passphrase=passphrase,
        always_trust=True
    )
    return str(decrypted_data)


#######################

def delete_file(file_name):
    """Deletes a file in the same folder where the function is called.

    Args:
        file_name (str): The name of the file to be deleted.

    Returns:
        bool: True if the file was deleted, False otherwise.
    """
    # get the current folder path
    current_folder = os.getcwd()

    # join the current folder path and the file name
    file_path = os.path.join(current_folder, file_name)

    # delete the file
    try:
        os.remove(file_path)
        return True
    except OSError:
        return False


####################################
key_type = 'RSA'
key_length = 1024
# name_email = 'Alice Bob <alice.bob@example.com>'
passphrase = 'Wdfg@#$546ER'

# # generate public and private key pair
# fingerprint = generate_key(key_type, key_length, name_email, passphrase)
# print(f'key fingerprint: {fingerprint}')

# # encrypt message with generated public key
# message = 'Hello, world! Meow-meow!! Welcome to websec cybersecuritytttt blog!'
# recipients = [fingerprint]
# print("ssssssssssss")
# print(recipients)
# #############
# encrypted_message = encrypt_message(message, recipients)
# print(f'encrypted message: {encrypted_message}')
############################
# encrypted_message = encrypt_message(key_file, message)
# print(encrypted_message)

# #################
# decrypted_data = decrypt_message(encrypted_message, passphrase)
# print("decrypted_data")
# print(decrypted_data)
# #############################
# delete_file_result = delete_file(fingerprint+".asc")
# if delete_file_result:
#     print("File deleted")
# else:
#     print("File not found or could not be deleted")
