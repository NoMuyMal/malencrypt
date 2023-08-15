#
# UPDATED 8/7/2023 3:45pm
# SCRIPT WILL ENCRPYT ANY FILE IN A DIRECTORY IT IS RAN. SCRIPT IS ONLY BUILT FOR LINUX.
# 
# KEY FILE AND PASSWORD (ENCRPYTED & HASHED) ARE CREATED AND MUST STAY WHERE THEY ARE CREATED
# (EncryptedPassword saved in cwd, .key saved in user's documents directory.)
# 
#
# CRYPTOGRAPHY MODULE REQUIRED
#

import time, sys, os, platform, hashlib, getpass

try:
    from cryptography.fernet import Fernet
except ModuleNotFoundError:
    print("\033[91m {}\033[00m" \
            .format("\nCrypography Module Not Installed! " \
                   "\nPlease use 'pip3 install cryptography'\n" ))
    exit()

if platform.system() != "Linux":    
    print("\033[91m {}\033[00m" \
        .format("\nThis script is only runnable on Linux!\n"))
    exit()

files = []
scriptName = os.path.basename(sys.argv[0])
passwdPresent = False
SHA256 = hashlib.new("SHA256")

# Creates string of both the key file that will be generated and its directory
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

os.chmod(thedir, 0o700) # Setting permissions for the key's directory for current user only

for file in os.listdir():
    
    if file == scriptName:
        continue
    if file == "EncryptedPassword":
        passwdPresent = True
        continue
    if os.path.isdir(file):
       continue
    
    files.append(file) # List of all files that will be encrypted/decrypted

def main():
    if passwdPresent:
        decrypt()
    else:
        encrypt()


def encrypt():
    if os.path.isfile(keydir): # triggers if key with the same name is already generated
        print("\033[91m {}\033[00m" \
                    .format("           There is already a key generated with the same directory name.\n" \
                            "        Or you might be missing the 'EncryptedPassword' file in this directory.\n" 
                            " Continuing will overwrite this key causing encrypted files to never be decrypted.\n"))
        warning = input(str("\n              Are you sure you want to continue (yes or no)?  "))
        print()
    
        while True:
            if warning.lower() == "yes":
                print()
                break
            elif warning.lower() == "no":
                print("Exiting program, key was not overwritten.\n")
                exit()
            else:
                warning = input(str("Invalid input, please type 'yes' or 'no': "))

   

    while True: 
        password = getpass.getpass(str("Please enter a password for later decryption: ")).encode()
        confirmPass = getpass.getpass(str("Enter the same password again to confirm: ")).encode()
        if password == confirmPass:
            break
        else:
            print("\nPasswords do not match. Please try again.\n")

# Creating Key
    key = Fernet.generate_key()

    with open(keydir, "wb") as theKey:
        theKey.write(key)
    
# Encrpyting password file
    with open("EncryptedPassword", "wb") as pwFile:
        SHA256.update(password) # hashes password before encrypting it
        pwEncrypted = Fernet(key).encrypt(SHA256.hexdigest().encode())
        pwFile.write(pwEncrypted)

    with open(keydir, "wb") as theKey:
        theKey.write(key)
        
# Perms of key, script, and password file all for current user only
    os.chmod ("EncryptedPassword" , 0o600)
    os.chmod(keydir, 0o700)
    os.chmod(scriptName, 0o700)

# Encrpyting Files
    for file in files:
        with open(file, "rb") as theFile:
         contents = theFile.read()
         contentsEncrypted = Fernet(key).encrypt(contents)
        with open(file, "wb") as theFile:
            theFile.write(contentsEncrypted)
    print("\n               Your files have been encrypted")

    print("\033[95m {}\033[00m" \
        .format("\nDo not remove the 'EncryptedPassword' file from this directory!" \
                "\n            This file is needed for decryption!\n"))

def decrypt():
    global counter
    counter = 0 # Counts wrong password entries
    
# Decrypts and comapres inputed and saved password
    password = getpass.getpass(str("Input a password to decrypt your files: ")).encode()
    SHA256 = hashlib.new("SHA256") # resets hash function
    SHA256.update(password)

    try:
        with open(keydir, "rb") as theKey:
            secretKey = theKey.read()

    except FileNotFoundError:
        print()
        print("\033[91m {}\033[00m" \
        .format("                        Key not found for this directory." \
                "\nMake sure you are the right user" \
                " or this directory's name has not changed since encryption."))
        exit()

    with open("EncryptedPassword", "rb") as passw:   
        savedPass = passw.read()
        
        try:
            decPass = Fernet(secretKey).decrypt(savedPass)
        except:
            print("\033[91m {}\033[00m".format("Invalid key! Could not decrypt files." \
            "\nThis program is using a different key than the one used to encrypt these files. "))
            exit()

# While loop to decrypt files and delete extra files
        while True:

            if SHA256.hexdigest().encode() == decPass:
           
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
                
                print("\n     Your files have been decrypted\n")
                break
    
    # Stops inputs to mitigate brute force attacks
            else:
                counter += 1
                if counter >= 3: 
                    print("\nWrong password entered" , counter , "times. "\
                          "Please wait" , counter , "seconds to try again.")
                        
                    time.sleep(counter)
                    
                    password = getpass.getpass(str("Try again: ")).encode()

                    SHA256 = hashlib.new("SHA256") # resets hash function
                    SHA256.update(password)

                else:
                     password = getpass.getpass(str("Wrong password. Please try again: ")).encode()
                     SHA256 = hashlib.new("SHA256")
                     SHA256.update(password)
main()
