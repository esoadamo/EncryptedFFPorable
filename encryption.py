import rsa
import rsa.common
import os
import pyaes
import hashlib


def gen_key_files(filename="rsa_key", size=2048, verbose=False, passphrase=None):
    """
    Generate new pair of keys and saves them to file
    :param filename: default rsa_key. path to the private key file. Public is filename.pub
    :param size: size of new keys, default 2048, accepts 512, 2048, 4096 etc.
    :param verbose: default False, when set to True prints info to console
    :param passphrase: optional, if not None, private key will be encrypted with this password string
    :return: tuple public_key, private_key
    """
    def p(s):
        if verbose:
            print(s)
    p('Generating %d bits %s...' % (size, filename))
    pub, priv = rsa.newkeys(size)
    p('Saving public key...')
    with open(filename + '.pub', 'wb') as f:
        f.write(pub.save_pkcs1())
    p('Saving private key...')
    with open(filename, 'wb') as f:
        if passphrase is None:
            f.write(priv.save_pkcs1())
        else:
            aes_key = generate_aes_password(passphrase)
            f.write(aes_encrypt_bytes(priv.save_pkcs1(), aes_key))
    p('Generating keys done')
    return pub, priv


def generate_aes_key(size=256):
    """
    Generates aes key with specified size
    :param size: aes bits, default 256
    :return: generated key bytes
    """
    return os.urandom(int(size / 8))


def generate_aes_password(password):
    """
    Creates a 256bits AES key from your password
    :param password: your passphrase
    :return: 256bit AES key
    """
    return bytes(hashlib.sha256(password.encode('utf8')).digest()[:32])


def load_key_files(filename="rsa_key", passphrase=None):
    """
    Loads 
    :param filename: default rsa_key, filename of the private key. Public key is private_key.pub
    :param passphrase: if not None, this string is used as password for the private key
    :return: tuple public_key, private_key
    """
    with open(filename + '.pub', 'rb') as f:
        key_pub = rsa.PublicKey.load_pkcs1(f.read())
    with open(filename, 'rb') as f:
        key_bytes = f.read()
        if passphrase is not None:
            aes_key = generate_aes_password(passphrase)
            key_bytes = aes_decrypt_bytes(key_bytes, aes_key)
        key_priv = rsa.PrivateKey.load_pkcs1(key_bytes)
    return key_pub, key_priv


def encrypt_file(file_plain, file_encrypted, public_key, aes_key_size=256):
    """
    Encrypts file with aes key which is saved with the file and encrypted by public key
    :param file_plain: path to the unencrypted file
    :param file_encrypted: path to the encrypted file
    :param public_key: public key used to encrypt aes key
    :param aes_key_size: AES key bits, default 256 
    :return: None
    """
    aes_key = generate_aes_key(aes_key_size)
    encrypted_aes_key = rsa.encrypt(aes_key, public_key)
    writer_encrypted_file = open(file_encrypted, 'wb')
    writer_encrypted_file.write(encrypted_aes_key)
    reader_plain_file = open(file_plain, 'rb')
    aes_encrypt_stream(reader_plain_file, writer_encrypted_file, aes_key)
    reader_plain_file.close()
    writer_encrypted_file.close()


def decrypt_file(file_encrypted, file_plain, public_key, private_key):
    """
    Decrypts file using your public and private key
    :param file_encrypted: path to the encrypted file
    :param file_plain: path to the unencrypted file
    :param public_key: public key used to encrypt AES password
    :param private_key: private key used to decrypt AES password
    :return: None
    """
    reader_encrypted_file = open(file_encrypted, 'rb')
    key_bytes_count = int(rsa.common.byte_size(public_key.n))
    key_bytes = reader_encrypted_file.read(key_bytes_count)
    key_aes = rsa.decrypt(key_bytes, private_key)
    writer_plain_file = open(file_plain, 'wb')
    aes_decrypt_stream(reader_encrypted_file, writer_plain_file, key_aes)
    reader_encrypted_file.close()
    writer_plain_file.close()


def aes_encrypt_stream(input_stream, output_stream, aes_key):
    """
    Encrypts stream
    :param input_stream: input stream plain bytes
    :param output_stream: output stream encrypted bytes
    :param aes_key: key used for encryption
    :return: None
    """
    aes_mode = pyaes.AESModeOfOperationCTR(aes_key)
    pyaes.encrypt_stream(aes_mode, input_stream, output_stream)


def aes_decrypt_stream(input_stream, output_stream, aes_key):
    """
    Encrypts stream
    :param input_stream: input stream encrypted bytes
    :param output_stream: output stream plain bytes
    :param aes_key: key used for encryption
    :return: None
    """
    aes_mode = pyaes.AESModeOfOperationCTR(aes_key)
    pyaes.decrypt_stream(aes_mode, input_stream, output_stream)


def aes_encrypt_bytes(input_bytes, aes_key):
    """
    Encrypt bytes with key
    :param input_bytes: plain bytes
    :param aes_key: key used to encrypt
    :return: encrypted bytes
    """
    aes = pyaes.AESModeOfOperationCTR(aes_key)
    return aes.encrypt(input_bytes)


def aes_decrypt_bytes(input_bytes, aes_key):
    """
    Decrypt bytes with key
    :param input_bytes: encrypted bytes
    :param aes_key: key used to decrypt
    :return: plain bytes
    """
    aes = pyaes.AESModeOfOperationCTR(aes_key)
    return aes.decrypt(input_bytes)
