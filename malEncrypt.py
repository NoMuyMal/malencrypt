#
# UPDATED 7/7/2023 5:07pm
# SCRIPT WILL ENCRPYT ANY FILE IN A DIRECTORY IT IS RAN. SCRIPT IS ONLY BUILT FOR LINUX.
# KEY FILE AND PASSWORD (ENCRPYTED) ARE CREATED AND MUST STAY WHERE THEY ARE CREATED (pw saved in cwd, .key saved in user's documents directory.)
# CRYPTOGRAPHY MODULE REQUIRED
#


import sys
import os
from cryptography.fernet import Fernet
import platform

if platform.system() != "Linux":
    print("\033[91m {}\033[00m" \
        .format("\nThis script is only runnable on Linux!\n"))
    exit()

files = []
scriptName = os.path.basename(sys.argv[0])
passwdPresent = False

# creates string of  both the key file that will be generated and its directory
keydir = os.path.expanduser("~") + "/Documents/malEncrypt/key_" +     \
         os.path.basename(os.getcwd()) + ".key"

thedir = os.path.expanduser("~") + "/Documents/malEncrypt"

if not os.path.isdir(thedir):
    try:
        os.mkdir(os.path.expanduser("~") + "/Documents/")
        print()
    except FileExistsError:
        print()
    os.mkdir(thedir)

else:
    print()

os.chmod(thedir, 0o700) # setting permissions for the key's directory

for file in os.listdir():
    
    if file == scriptName:
        continue
    if file == "EncryptedPassword":
        passwdPresent = True
        continue
    if os.path.isdir(file):
       continue
    
    files.append(file) # all files that will be encrypted


def main():
    if passwdPresent:
        decrypt()
    else:
        encrypt()


def encrypt():
    password = input(str("Please enter a password for decryption: ")).encode()

#Creating Key
    key = Fernet.generate_key()

    with open(keydir, "wb") as theKey:
        theKey.write(key)
    
#Encrpyting pw file
    with open("EncryptedPassword", "wb") as pwFile:
        pwEncrypted = Fernet(key).encrypt(password)
        pwFile.write(pwEncrypted)
        
    with open(keydir, "wb") as theKey:
        theKey.write(key)
        
    os.chmod ("EncryptedPassword" , 0o600)
    os.chmod(keydir, 0o700)
#Encrpyting Files
    for file in files:
        with open(file, "rb") as theFile:
         contents = theFile.read()
         contentsEncrypted = Fernet(key).encrypt(contents)
        with open(file, "wb") as theFile:
            theFile.write(contentsEncrypted)
    print("       Your files have been encrypted")

    print("\033[95m {}\033[00m" \
        .format("\nDo not remove the 'EncryptedPassword' file from this directory!" \
            "\n       This file is needed for decryption!"))

def decrypt():

#decrypts and comapres inputed and saved password
    password = input(str("Input a password to decrypt your files: ")).encode()
    
    try:
        with open(keydir, "rb") as theKey:
            secretKey = theKey.read()

    except FileNotFoundError:
        print()
        print("Key not found for this directory. Make sure you are the right user.")
        exit()

    with open("EncryptedPassword", "rb") as passw:   
        savedPass = passw.read()
        
        try:
            decPass = Fernet(secretKey).decrypt(savedPass)
        except:
            print("\033[91m {}\033[00m".format("Invalid key! Could not decrypt files." \
            "\nThis program is using a different key than the one used to encrypt these files. "))
            exit()

#While loop to decrypt files and delete extra files
        while True:

            if password == decPass:
           
                for file in files:
                    with open(file, "rb") as theFile:
                        contents = theFile.read()
                        contentsDec = Fernet(secretKey).decrypt(contents)
                    with open(file, "wb") as theFile:
                        theFile.write(contentsDec)
                
                passw.close()

                removeFiles = ["EncryptedPassword", keydir]
                for file in removeFiles:
                    if file in removeFiles:
                        os.unlink(file)
                
                print("       Your files have been decrypted")
                break
            else:
                password = input(str("Wrong password. Please try again: ")).encode()

main()
