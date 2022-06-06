from Crypto.Cipher import AES
import sqlite3
from base64 import b64decode, b64encode
import sys, os
import signal
import argparse



def handler(signum, frame):
    print("Exiting...")
    sys.exit(0)

def store_credentials(username,password,website,key):
    dataUser = bytearray(username.encode())
    dataPass = bytearray(password.encode())
    masterKey = bytearray(key.encode())
    try:
        # Could perhaps use EAX mode instead of GCM
        cipherUser = AES.new(masterKey, AES.MODE_GCM)
        nonceUser = cipherUser.nonce
        ciphertextUser, tagUser = cipherUser.encrypt_and_digest(dataUser)
        cipherPass = AES.new(masterKey, AES.MODE_GCM)
        noncePass = cipherPass.nonce
        ciphertextPass, tagPass = cipherPass.encrypt_and_digest(dataPass)
        cursor.execute("INSERT INTO passwords VALUES(?,?,?,?,?,?,?)", (b64encode(ciphertextUser).decode('utf-8'), b64encode(ciphertextPass).decode('utf-8'), website,b64encode(noncePass).decode('utf-8'), b64encode(tagPass).decode('utf-8'), b64encode(nonceUser).decode('utf-8'),b64encode(tagUser).decode('utf-8')))
        connection.commit()
        print("[+] Credentials added successfully")
    except:
        print("[-] Something went wrong :/")

def read_database(key):
    key = bytearray(key.encode())
    usernames = []
    passwords = []
    websites = []
    for row in cursor.execute("SELECT * FROM passwords"):
        cipherUser = b64decode(row[0])
        cipherPass = b64decode(row[1])
        website = row[2]
        noncePass = b64decode(row[3])
        tagPass = b64decode(row[4])
        nonceUser = b64decode(row[5])
        tagUser = b64decode(row[6])
        try:
            AESPass = AES.new(key, AES.MODE_GCM, nonce=noncePass)
            plaintextPass = AESPass.decrypt(cipherPass)
            AESPass.verify(tagPass)
            passwords.append(plaintextPass.decode())
            AESUser = AES.new(key, AES.MODE_GCM, nonce=nonceUser)
            plaintextUser = AESUser.decrypt(cipherUser)
            AESUser.verify(tagUser)
            usernames.append(plaintextUser.decode())
            websites.append(website)
        except:
            pass

    print("---------------------------------------------------------------------------")
    for i in range(0, len(usernames)):
        print("Username: " + usernames[i] + "\nPassword: " + passwords[i] + "\nWebsite: " + websites[i])
        print("---------------------------------------------------------------------------")


if __name__ == "__main__":
    # trap ctrl C for smooth exit
    signal.signal(signal.SIGINT, handler)
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()
    # create table to store passwords if it doesn't exist
    cursor.execute("CREATE TABLE IF NOT EXISTS passwords(ciphertextUser text, ciphertextPass text, website text, noncePass text, tagPass text, nonceUser text, tagUser text)")
    # for single command execution mode
    parser = argparse.ArgumentParser(description='Store credentials with AES Galois/Counter mode 128b encryption. You can also use different master keys to encrypt and decrypt different passwords in the same database. Do not add arguments for interactive mode', prog="python3 FastPass.py")
    parser.add_argument("-s","--store", action="store_true", help="Store the credentials in the database")
    parser.add_argument("-u","--username",help="Username to encrypt")
    parser.add_argument("-p", "--password",help="Password to encrypt")
    parser.add_argument("-w","--website",help="Website/company/usage of the credentials (unencrypted)")
    parser.add_argument("-r","--read", action="store_true", help="Read the current database with a master key")
    parser.add_argument("-k","--key",help="Master key used to unencrypt some/all the credentials")
    args=vars(parser.parse_args())

    if args["store"] == True:
        if args["read"] == True:
            print("[-] Can't read and store at the same time!")
            sys.exit(1)
        if args["username"] is not None:
            if args["password"] is not None:
                if args["key"] is not None:
                    store_credentials(args["username"],args["password"],args["website"],args["key"])
                    sys.exit(0)
        else:
            print("[-] Not enough arguments!")
            sys.exit(1)
    if args["read"] == True:
        if args["store"] == True:
            print("[-] Can't read and store at the same time!")
            sys.exit(1)
        if args["key"] is not None:
            read_database(args["key"])
            sys.exit(0)
        else:
            print("[-] Not enough arguments!")
            sys.exit(1)

    # interactive mode
    while True:
        choice = input("(s) Store Credentials/(r) Read Credentials/(q) Quit: ")
        if choice == "s":
            dataUser = bytearray(input("Input username: ").encode())
            dataPass = bytearray(input("Input password: ").encode())
            website = input("Input website/game it is for (optional): ")
            masterKey = bytearray(input("Input master Key (16 characters): ").encode())
            try:
                # Could perhaps use EAX mode instead of GCM
                cipherUser = AES.new(masterKey, AES.MODE_GCM)
                nonceUser = cipherUser.nonce
                ciphertextUser, tagUser = cipherUser.encrypt_and_digest(dataUser)
                cipherPass = AES.new(masterKey, AES.MODE_GCM)
                noncePass = cipherPass.nonce
                ciphertextPass, tagPass = cipherPass.encrypt_and_digest(dataPass)
                cursor.execute("INSERT INTO passwords VALUES(?,?,?,?,?,?,?)", (b64encode(ciphertextUser).decode('utf-8'), b64encode(ciphertextPass).decode('utf-8'), website, b64encode(noncePass).decode('utf-8'), b64encode(tagPass).decode('utf-8'), b64encode(nonceUser).decode('utf-8'),   b64encode(tagUser).decode('utf-8')))
                connection.commit()
                print("[+] Credentials added successfully")
            except:
                print("[-] Something went wrong :/")
        elif choice == "r":
            key = bytearray(input("Input master key: ").encode())
            usernames = []
            passwords = []
            websites = []
            for row in cursor.execute("SELECT * FROM passwords"):
                cipherUser = b64decode(row[0])
                cipherPass = b64decode(row[1])
                website = row[2]
                noncePass = b64decode(row[3])
                tagPass = b64decode(row[4])
                nonceUser = b64decode(row[5])
                tagUser = b64decode(row[6])
                try:
                    AESPass = AES.new(key, AES.MODE_GCM, nonce=noncePass)
                    plaintextPass = AESPass.decrypt(cipherPass)
                    AESPass.verify(tagPass)
                    passwords.append(plaintextPass.decode())
                    AESUser = AES.new(key, AES.MODE_GCM, nonce=nonceUser)
                    plaintextUser = AESUser.decrypt(cipherUser)
                    AESUser.verify(tagUser)
                    usernames.append(plaintextUser.decode())
                    websites.append(website)
                except:
                    pass

            print("---------------------------------------------------------------------------")
            for i in range(0,len(usernames)):
                print("Username: "+usernames[i]+"\nPassword: "+passwords[i]+"\nWebsite: "+websites[i])
                print("---------------------------------------------------------------------------")
        elif choice == "q":
            sys.exit(0)