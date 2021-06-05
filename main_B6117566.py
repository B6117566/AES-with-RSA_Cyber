from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15 as PKCS1
import time


def Signature_PKCS1(name, final_cipherText):
    key_rsa = RSA.import_key(open(name + ".RSA_private.pem").read())
    hash_cipherText = SHA512.new(final_cipherText)
    signature = PKCS1.new(key_rsa).sign(hash_cipherText)

    with open(name + '.Signed.txt', 'wb') as file:
        file.write(signature)

    print('='*50)
    print("Digitally Signed File. \n-->",
          name + '.Signed.txt Successful.')
    print('='*50)


def Verify_Signature_PKCS1(name, cipherText):
    key_rsa = RSA.import_key(open(name + ".RSA_public.pem").read())
    hash_cipherText = SHA512.new(cipherText)
    signature = open(name + '.Signed.txt', 'rb').read()
    print('='*50, '\n')
    try:
        PKCS1.new(key_rsa).verify(hash_cipherText, signature)
        print("The signature is valid.")
        print("File has not been tampered.")
        check = True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        print("File has been tampered.")
        check = False

    print('='*50, '\n')
    return check


def RSA_KeyGen(name):
    bits = 2048
    key = RSA.generate(bits)
    private_key = key.export_key()
    with open(name + ".RSA_private.pem", "wb") as output_file:
        output_file.write(private_key)

    public_key = key.publickey().export_key()
    with open(name + ".RSA_public.pem", "wb") as output_file:
        output_file.write(public_key)

    print('='*50)
    print('Generate RSA -', bits, ' Successful.')
    print('='*50)


def AES_KeyGen(name):
    # Generate the key
    # 16, 24 or 32 bytes long
    # (respectively for AES-128, AES-192 or AES-256).
    bits = 32
    key = get_random_bytes(bits)
    with open(name + '.AES_Key.txt', 'wb') as output_file:
        output_file.write(key)

    print('='*50)
    print('Generate Key AES -', bits*8, ' Successful.')
    print('='*50)
    return key


def AES_Encrypt(input_file):
    # Encrypt AES-OFB
    plainText = open(input_file, 'rb').read()
    name_file_split = input_file.split('.')

    '''
    the Initialization Vector. It must be unique for the combination message/key. 
    It is as long as the block size (e.g. 16 bytes for AES). 
    If not present, the library creates a random IV.
    '''
    iv = get_random_bytes(16)
    key = AES_KeyGen(name_file_split[0])
    Encryptor = AES.new(key, AES.MODE_OFB, iv=iv)

    cipherText = Encryptor.encrypt(plainText)
    final_cipherText = iv + cipherText

    with open('enc.' + input_file, 'wb') as output_file:
        output_file.write(final_cipherText)

    if name_file_split[1] == 'txt':
        RSA_KeyGen(name_file_split[0])
        Signature_PKCS1(name_file_split[0], final_cipherText)

    print('')
    print('*'*50)
    print('Encrypt file name.\n--> ',
          input_file, ' Complete.')
    print('*'*50)


def AES_Decrypt(input_file):
    # Decrypt AES-OFB
    cipherText = open(input_file, 'rb')
    name_file_split = input_file.split('.')

    if name_file_split[2] == 'txt':
        if not Verify_Signature_PKCS1(
                name_file_split[1], (open(input_file, 'rb').read())):
            print('\nPlease use file Signed correct. Try Again', '\n', '-'*50)
            return

    key = open(name_file_split[1] + '.AES_Key.txt', 'rb').read()
    iv = cipherText.read(16)
    cipherText = cipherText.read()
    Encryptor = AES.new(key, AES.MODE_OFB, iv=iv)

    try:
        plainText = Encryptor.decrypt(cipherText)
    except:
        print('Please use file AES-Key correct. Try Again')
        return

    with open('dec.' + name_file_split[1] + '.' + name_file_split[2], 'wb') as output_file:
        output_file.write(plainText)

    print('')
    print('*'*50)
    print('Decrypt file name.\n--> ',
          name_file_split[1] + '.' + name_file_split[2], ' Complete.')
    print('*'*50)


while True:
    print('Please selector mode Encrypt or Decrypt.')
    print('1. Encrypt.')
    print('2. Decrypt.')
    print('0. Exit.')
    print('='*50)
    selector = input('--> ')
    print("\033c")
    length_space = 20

    if selector.isnumeric():
        selector = int(selector)

        if selector == 1:
            print('>'*length_space, '(Encryption)', '<'*length_space)
            input_file = input(
                'Please type (name file + name file extension) you want.\n --> ')
            print('')
            AES_Encrypt(input_file)

        elif selector == 2:
            print('>'*length_space, '(Decryption)', '<'*length_space)
            input_file = input(
                'Please type (name file + name file extension) you want.\n --> ')
            print('')
            AES_Decrypt(input_file)

        elif selector == 0:
            exit()

        time.sleep(6)
        print('*'*(length_space*2))
        print("\033c")

    else:
        print("Please type select correct. Try Again!!")
        time.sleep(3)
        print("\033c")
        continue
