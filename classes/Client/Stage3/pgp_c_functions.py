import gnupg
import os
import random
import string


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
# random string


def session_random_string(length):
    # Create a string of all possible characters
    characters = string.ascii_letters + string.digits + string.punctuation
    # Use random.choices to select a random character from the string for each position
    result = "".join(random.choices(characters, k=length))
    # Return the generated string
    return result


####################################
key_type = 'RSA'
key_length = 1024
