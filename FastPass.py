from Crypto.Cipher import AES
import sqlite3
from base64 import b64decode, b64encode

"""
Add
key=b'TestVar123456789'

cipher = AES.new(key, AES.MODE_GCM)
nonce = cipher.nonce
data=b"S3curePas2sord"
ciphertext, tag = cipher.encrypt_and_digest(data)

connection=sqlite3.connect("test.db")
cursor=connection.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS passwords(username text, ciphertext text, nonce text, tag text)")
cursor.execute("INSERT INTO passwords VALUES('gcmTest','"+b64encode(ciphertext).decode('utf-8')+"', '"+b64encode(nonce).decode('utf-8')+"', '"+b64encode(tag).decode('utf-8')+"')")
connection.commit()
connection.close()
"""
"""
Retrieve
connection=sqlite3.connect("test.db")
cursor=connection.cursor()
for row in cursor.execute("SELECT * FROM passwords"):
    username=row[0]
    cipherPass=b64decode(row[1])
    nonce=b64decode(row[2])
    tag=b64decode(row[3])
    key=bytearray(input("Input key to decipher").encode())
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(cipherPass)
        cipher.verify(tag)
        print("Password for user "+username+": ", plaintext.decode())
    except ValueError:
        print("Key incorrect or message corrupted")
"""

if __name__=="__main__":
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS passwords(username text, ciphertext text, website text, nonce text, tag text)")
    while True:
        choice=input("(a) Add Credentials/ (s) See Credentials: ")
        if choice == "a":
            username=input("Input username: ")
            data=bytearray(input("Input password: ").encode())
            website= input("Input website/game it is for (optional): ")
            masterKey=bytearray(input("Input master Key (16 characters): ").encode())
            try:
                cipher = AES.new(masterKey, AES.MODE_GCM)
                nonce = cipher.nonce
                ciphertext, tag = cipher.encrypt_and_digest(data)
                cursor.execute("INSERT INTO passwords VALUES(?,?,?,?,?)",(username,b64encode(ciphertext).decode('utf-8'),website,b64encode(nonce).decode('utf-8'),b64encode(tag).decode('utf-8')))
                connection.commit()
                print("[+] Credentials added successfully")
            except :
                print("[-] Something went wrong :/")
        elif choice == "s":
            key = bytearray(input("Input master key: ").encode())
            usernames=[]
            passwords=[]
            websites=[]
            for row in cursor.execute("SELECT * FROM passwords"):
                username = row[0]
                cipherPass = b64decode(row[1])
                website=row[2]
                nonce = b64decode(row[3])
                tag = b64decode(row[4])
                try:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt(cipherPass)
                    cipher.verify(tag)
                    usernames.append(username)
                    passwords.append(plaintext.decode())
                    websites.append(website)
                except:
                    print("[-] Incorrect master key!")
            for i in range(0,len(usernames)):
                print("---------------------------------------------------------------------------")
                print("Username: "+usernames[i]+"\nPassword: "+passwords[i]+"\nWebsite: "+websites[i])
                print("---------------------------------------------------------------------------")