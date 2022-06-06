from Crypto.Cipher import AES
import sqlite3
from base64 import b64decode, b64encode
import sys, os
import signal


def handler(signum, frame):
    print("Exiting...")
    sys.exit(0)


if __name__ == "__main__":
    # trap ctrl C for smooth exit
    signal.signal(signal.SIGINT, handler)
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()
    # create table to store passwords if it doesn't exist
    cursor.execute("CREATE TABLE IF NOT EXISTS passwords(ciphertextUser text, ciphertextPass text, website text, noncePass text, tagPass text, nonceUser text, tagUser text)")
    while True:
        choice = input("(a) Add Credentials/(s) See Credentials/(q) Quit: ")
        if choice == "a":
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
        elif choice == "s":
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