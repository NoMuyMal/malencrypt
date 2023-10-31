#
# UPDATED 10/31/2023 12:00 PM CDT
#
# Program used to encrypt files in a Linux directory with AES 128 symmetric encryption
# Users manage their own keys and passwords to encrypt files for decryption later
# Look at README for more information
# BUILT TO BE USED IN LINUX ONLY
#

try:
    from cryptography.fernet import Fernet
except ModuleNotFoundError:
    print("Install cryptography with 'pip install cryptography'")
    exit()

import getpass
import hashlib
import os
import platform
import sys
import time


print("\n                     WELCOME TO MALENCRYPT"            )
print("       Enter one of the letters below to run a command\n")

# This is the directory where keys, passwords, logs are saved. format: ~/Documents/malEncrypt
maindir = os.path.expanduser("~") + "/Documents/malEncrypt"

# Creates directory for this program to operate in if not already created
if not os.path.isdir(maindir):

    try:
        os.mkdir(os.path.expanduser("~") + "/Documents/")
    except FileExistsError:
        print()

    os.mkdir(maindir)
    os.chmod(maindir, 0o700)
    
if not os.path.isdir(maindir + "/Passwords/"):
    os.mkdir(maindir + "/Passwords/")
    os.chmod(maindir + "/Passwords/" , 0o700)

if not os.path.isdir(maindir + "/Logs/"):
    os.mkdir(maindir + "/Logs/")
    os.chmod(maindir + "/Logs/" , 0o700)

    with open(maindir + "/Logs/malEncryptLog", "a+") as log:
        log.write("                  BEGINNING OF MALENCRYPT LOG               \n")
        log.write(f"{'TYPE':<6} | {'TIME':^26} | {'FUNCTION':^15} | {'MESSAGE'}\n")


#####################################################################################################################

# Function to let user select other functions
def main():

    if platform.system() != "Linux":
        print("This script is only runnable on Linux!\n")
        return

    selection = ""

    while True:
        selection = input(str("(E)Encrypt | (D)Decrpyt | (C)Create or (R)Remove Key | (Q)Quit: "))

        if selection.lower() == "e" or selection.lower() == "encrypt":
            encrypt()
            main()
            break

        elif selection.lower() == "d" or selection.lower() == "decrypt":
            decrypt()
            main()
            break

        elif selection.lower() == "c" or selection.lower() == "create":
            keyGen()
            main()
            break

        elif selection.lower() == "r" or selection.lower() == "remove":
            removeKey()
            main()
            break

        elif selection.lower() == "q" or selection.lower() == "quit":
            print("\n\nThanks for using malEncrypt2.0!\n")
            break

        # elif selection.lower() == "t":
        #     test()
        #     break

        else:
            print(selection, "is not a valid entry. Please try again \n")


#####################################################################################################################

# Function to encrypt files in current directory with chosen key
def encrypt():

    counter = 2 # Counter used to add digits to the end of password file name to mitigate overwriting passwords
    SHA256 = hashlib.new("SHA256") # for hashing password file

    # Method returns true if keys have been created
    if not confirmKeysCreated():
        print("No key has been created for this user yet.\n")
        return


    # If only one key has been created, that key is automatically selected.
    if len(os.listdir(maindir)) <= 3:
        for item in os.listdir(maindir):
            if ".key" in item:
                keyName = item
                keyPath = maindir + "/" + item
                print(f"\n{keyName} has been selected.\n") 
    else:
    
        print("\nInsert a name for the key you want to encrypt with or 'L' for list of existing keys: ")
        keyPath, keyName = getKeyName()

        while keyName + ".key" not in os.listdir(maindir) and keyPath != "q":
            print("\nKey not found. The selection is case sensitive. Please try again: ")
            keyPath, keyName = getKeyName()
        
        # If user quit during key selection
        if keyPath == 'q':
            print()
            return
        

    # While loop for creating valid password
    while True: 
        password = getpass.getpass(str("\nPlease enter a password for later decryption: ")).encode()

    # If user wants to quit or if password length is too short are handled here
        if password.lower() == 'q'.encode():
            print("Cancelling encryption.\n")
            return

        if len(password) < 3:
            print("Password must be at least 3 characters. Please try again.")
            continue

        confirmPass = getpass.getpass(str("Enter the same password again to confirm: ")).encode()
        
    # While loop is broken if users confirms password is correct
        if password == confirmPass:
            break
        else:
            print("\nPasswords do not match. Please try again.")
    
    SHA256.update(password) # Creates hash digest of password to save


    # Opening key file to encrypt password and files
    with open(keyPath, "rb") as keyFile:
        key = keyFile.read()

    # passwordLocation variable saves password in format: ~/Documents/malEncrypt/Passwords/key_directory_Password
        passwordLocation = maindir + "/Passwords/" + keyName.replace(".key","") + "_" + \
                            os.path.basename(os.getcwd()) + "_password"

    # If any file in saved passwords includes current directory, user is informed
        cont = 'yes'                    

        for passwordFile in os.listdir(maindir + "/Passwords/"):
            if os.path.basename(os.getcwd()) in passwordFile:

                print("\n    A directory with the same name has already been encrypted")
                print("Make sure this directory is not already encrypted before proceeding")
                cont = input("    Are you sure you want to continue (yes or no)?  ")
                print()
                break

        if cont.lower() != 'yes':
            print("\nCancelling Encryption.\n")
            return

    # While loop to change a password's name incase a duplicate password exists
        while os.path.isfile(passwordLocation):
        
        # If no number is after password file name, 2 is added to the end of the name. e.g. key_dir_password2
            if passwordLocation[-1] == 'd':
                passwordLocation = passwordLocation + '2'
      
        # If pasword name already has number, the counter counts up until new number is found to replace old number. e.g. key_dir_password3
            elif passwordLocation[-1] != str(counter):
                passwordLocation = passwordLocation[:-1] + str(counter)

            counter += 1

    # Saving encrypted digest of password entered
        with open(passwordLocation, "wb") as passwordFile:
            passwordFile.write(Fernet(key).encrypt(SHA256.hexdigest().encode()))

            os.chmod(passwordLocation , 0o600) # Edits perms for only current user to access'
            writeLog("ENCRYPT", f"{passwordLocation.replace(maindir + '/Passwords/', '')} was saved")

        # Gather files and encrpyts them with chosen key
        files = gatherFiles()

        for file in files:      

            with open(file, "rb") as theFile:
                contents = theFile.read()
                contentsEncrypted = Fernet(key).encrypt(contents)

            with open(file, "wb") as theFile:
                theFile.write(contentsEncrypted)

        print("\nYour files have been encrypted\n")
        writeLog("ENCRYPT", f"{os.getcwd()} directory was encrypted with {keyName}.key")


####################################################################################################################

# Function to decrypt files in current directory with chosen key
def decrypt():

    SHA256 = hashlib.new("SHA256") # create hash function
    passwordList = [] # Initialized list for passwords chosen by program for decryption
    passwDecryptSuccess = False
    counter = 0 # Counts number of failed password entries
    
    # Method returns true if keys have been created
    if not confirmKeysCreated():
        print("No key has been created for this user yet.\n")
        return
    
    # If only one key has been created, that key is automatically selected.
    if len(os.listdir(maindir)) <= 3:
        for item in os.listdir(maindir):
            if ".key" in item:
                keyName = item
                keyPath = maindir + "/" + item 
                print(f"\n{keyName} has been selected.\n") 
    else:
        # Gets key name and file path to decrypt files. If user enters q, quits function.
        print("\nInsert a name for the key you want to decrypt with or 'L' for list of existing keys: ")
        keyPath, keyName = getKeyName()
        
        while keyName + ".key" not in os.listdir(maindir) and keyPath != "q":
            print("\nKey not found. The selection is case sensitive. Please try again: ")
            keyPath, keyName = getKeyName()
        
        if keyPath == 'q':
            print()
            return

    # If valid key, the key file will be opened for decryption
    with open(keyPath, "rb") as key:
        openedKey = key.read()


    # Gathers available passwords with the current directory in then name for possible decryption
    for item in os.listdir(maindir + "/Passwords/"):
        if os.path.basename(os.getcwd()) in item:
            passwordList.append(item)

    # Each password will try to be decrypted until there is a success
    for password in passwordList:
        with open(maindir + "/Passwords/" + password) as currentPassword:
            openedPassword = currentPassword.read()
            
            try: 
                decrpytedPassword = Fernet(openedKey).decrypt(openedPassword)
                passwDecryptSuccess = True
                correctPasswordPath = maindir + "/Passwords/" + password
                break
            except:
                continue
    
    # If no password was able to be decrypted previously, program will find all passwords with the key name to give user a selection
    if passwDecryptSuccess == False:
        passwordList = []

        for item in os.listdir(maindir + "/Passwords/"):
            if keyName in item:
                passwordList.append(item)
    
    # If there is no matching key name or directory, program has nothing to decrypt.
        if passwordList == []:
            print("\nThere is nothing encrypted that match this key or directory.\n")
            return

        print("\nPassword for this directory not found. If the directory's name changed, select password with the previous name.")
        print("            Please type the name of the password you want to choose below or type 'q' to cancel.\n")
        print(*passwordList , "\n")

    # While loop for taking valid password input
        while True:
            password = input()
            if password in passwordList:
                break
            if password.lower() == 'q':
                print("\nCancelling decryption.\n")
                return
            else:
                print("\nInvalid choice, please try again. Selection is case sensitive.")

    # Opening chosen password and trying to decrypt it
        with open(maindir + "/Passwords/" + password) as currentPassword:
            openedPassword = currentPassword.read()
            
            try: 
                decrpytedPassword = Fernet(openedKey).decrypt(openedPassword)
                passwDecryptSuccess = True
                correctPasswordPath = maindir + "/Passwords/" + password 
            except:
                print(f"\n{password} failed to be decrypted with {keyName}.key\n")
                writeLog("DECRYPT", f"Error decrypting {password} with {keyName}.key for directory {os.getcwd()}")
                return


    # If a password is decrypted successfully, the program will begin to decrypt files
    if passwDecryptSuccess:
            inputPassword = getpass.getpass(str("Input a password to decrypt your files: ")).encode()

        # If user wants to quit decrypting
            if inputPassword.lower() == "q".encode():
                print("\nCancelling decryption.\n")
                return
    
            SHA256.update(inputPassword)
            
        # While loop until user enters correct password before decrypting
            while True:

            # If the digest of inpputed password is equal to the digest of the saved password decrypting begins
                if SHA256.hexdigest().encode() == decrpytedPassword:
                    
                    files = gatherFiles() # gathers list of files from current directory
                    decryptError = False # Initialized for error decrypting any files
                    print()

                # Decrypting files in current directory
                    for file in files:
                        with open(file, "rb") as currentFile:
                            contents = currentFile.read()
                            
                        # If there is an error decrypting a file, user will be warned and error will be noted
                            try:
                                decryptedContents = Fernet(openedKey).decrypt(contents)
                            except:
                                print("\n  !! Error decrypting file:", file, "!!")
                                writeLog("DECRYPT", f"Error decrypting file: {file} with key {keyName}.key")
                                decryptError = True
                                continue
                            
                    # If there is a permission error while writing decrypted contents, user is informed.
                        with open(file, "wb") as currentFile:
                            currentFile.write(decryptedContents)

                
                    if decryptError:
                        print("\n Any other files were decrypted successfully.")
                        print("   Please check logs for more information.\n")

                    # Saves password for debugging and writes error to log
                        if "debug" not in password:
                            debugPasswordPath = maindir + "/Passwords/" + password + "_debug"
                        else:
                            debugPasswordPath = maindir + "/Passwords/" + password

                        os.replace(correctPasswordPath, debugPasswordPath)
                        writeLog("DECRYPT", f"Error detected decrypting {os.getcwd()} with key {keyName}.key, saving password: {debugPasswordPath}")
              
                # If there is no error, used password will be deleted  
                    else:
                        print("All files decrypted successfully.\n")
                        os.unlink(correctPasswordPath) # deletes password file after decryption
                        
                        writeLog("DECRYPT", f"{password} was used successfully and deleted.")
                        writeLog("DECRYPT", f"{os.getcwd()} was decrypted successfully with {keyName}.key")

                    break
            
            # Runs if user inputted the incorrect password #! do something about script restarting
                else:

                # Incase user wants to quit
                    if inputPassword.lower() == "q".encode():
                        print("\nCancelling decryption.\n")
                        return


                    counter += 1
                    if counter >= 3: 
                        print("\nWrong password entered" , counter , "times. "\
                            "Please wait" , counter , "seconds to try again.")
                            
                        time.sleep(counter)
                        
                        inputPassword = getpass.getpass(str("Try again: ")).encode()

                   


                        SHA256 = hashlib.new("SHA256") # resets hash function
                        SHA256.update(inputPassword)

                    else:
                        inputPassword = getpass.getpass(str("Wrong password. Please try again: ")).encode()
                        SHA256 = hashlib.new("SHA256")
                        SHA256.update(inputPassword)

    else:
        print("Key could not decrypt a password file.")
        print()
        writeLog("DECRYPT", f"{keyName}.key was not able to decrypt any passwords for directory {os.getcwd()}")


#####################################################################################################################

# Fucntion for used to create new key
def keyGen():
    
    print("\nInsert a name for the key you want to create or 'L' for list of existing keys: ")
    keyPath, keyName = getKeyName()

    
    while len(keyName) < 3 and keyPath != "q":
        print("Please enter at least three characters for the key name.")
        keyPath, keyName = getKeyName()

    # Key must be alphanumeric
    while not keyName.isalnum() and keyPath != "q":
        print("Please enter a key name with no special characters.")
        keyPath, keyName = getKeyName()

    if keyPath.lower() == 'q':
        print()
        return

    if os.path.isfile(keyPath): # triggers if key with the same name is already generated
            print("\033[91m {}\033[00m" \
            .format("\n               There is already a key generated with the same name.\n" \
            "   Continuing will overwrite this key causing encrypted files to never be decrypted.\n"))
            
            warning = input(str("\n              Are you sure you want to continue (yes or no)?  "))
            print()
        
            while True:
                if warning.lower() == "yes":
                    print()
                    writeLog("GENERATE KEY", f"{keyName}.key was overwritten!")
                    break
                elif warning.lower() == "no":
                    print("Cancelling. Key was not overwritten.\n")
                    return
                else:
                    warning = input(str("Invalid input, please type 'yes' or 'no': "))

    # If user does not add .key file extension, program does it automatically   

    key = Fernet.generate_key() # generates key 128 bit

    with open(keyPath, "wb") as theKey:
        theKey.write(key)
        
    os.chmod(keyPath, 0o700)

    print()
    print(keyName, "key generated!\n")
    writeLog("GENERATE KEY", f"{keyName}.key generated")


#####################################################################################################################

# Funciton for user to delete key
def removeKey():

    # Variable determines if user wants to continue with deleting key
    cont = 'no'

    # Method returns true if keys have been created
    if not confirmKeysCreated():
        print("No key has been created for this user yet.\n")
        return


    # Grabs key path and key name to remove key, if user types q function quits   
    print("Insert a name for the key you want to remove or 'L' for list of existing keys: ")
    keyPath, keyName = getKeyName()

    
    while keyName + ".key" not in os.listdir(maindir) and keyPath != "q":
        print("Key not found. The selection is case sensitive. Please try again: ")
        keyPath, keyName = getKeyName()

    if keyPath.lower() == 'q':
        print()
        return


    # If password file has keyname in it, there is still files encrypted with that key
    for file in os.listdir(maindir + "/Passwords/"):
        if keyName in file:
            print()
            print("       There are files encrypted with this key still")
            print("Deleting the key will cause these files to be unrecoverable")
            break

    # Even if there are no files encrypted with key, still asking if user wants to delete key
    cont = input("\nAre you sure you want to delete the %s key (yes or no)?  " % keyName)


    if cont.lower() == 'yes':
        os.unlink(keyPath)
        print(f"\n{keyName}.key has been deleted.\n")
        writeLog("REMOVE KEY", f"{keyName}.key deleted")
    else:
        print("No key was deleted.\n")


#####################################################################################################################

# Function for getting user to select a key
def getKeyName():

    # While loop to let user select a key after listing them
    while True:

        # remove this and print key name input per function 
        keyName = input(str())

        # List all keys if user entered 'l'
        if keyName.lower() == 'l':

        # Method returns true if keys have been created
            if not confirmKeysCreated():
                print("No keys generated yet. Please enter a name of a key to generate: ")
            else:
                print()
                for item in os.listdir(maindir):
                    if ".key" in item:
                        print(item.replace(".key", ""))

                print("\nChoose a key above: ")
    
    # Breaks loop if user does not want to list keys
        else:
            break

    # Incase user wants to the to quit the calling function
    if keyName.lower() == 'q':
        return 'q' , ""
    
    # Defines the key's whole file path
    keyPath = os.path.expanduser("~") + "/Documents/malEncrypt/" + keyName + ".key"

    return keyPath, keyName


#####################################################################################################################

# Function used to gather files for encryption or decrpytion
def gatherFiles():

    # List initialized to collect all files within a directory
    files = []

    for file in os.listdir(): # adds files to list except for script and directories

    # These files are not added to the list
        if file == os.path.basename(sys.argv[0]): # if file == name of script
            continue
        if os.path.isdir(file):
            continue
        if file in files: # makes sure there are no duplicate files
            continue

    # If user does not have perms for file, it is skipped
        if not os.access(file, os.R_OK):
            if not os.access(file, os.W_OK):
                print(f"\nNo read or write permissions greanted to file: {file}")
                continue
            else:
                print(f"\nNo read permissions greanted to file: {file}")
                continue

        if not os.access(file, os.W_OK):
            print(f"\nNo write permissions greanted to file: {file}")
            continue


        files.append(file)
    

    return files


#####################################################################################################################

# Function used to confirm keys are created before running other functions
def confirmKeysCreated():
    
    # Returns true if there are keys created
    keyPresent = False

    for item in os.listdir(maindir):
        if ".key" in item:
            keyPresent = True
            break
        else:
            continue

    return keyPresent


#####################################################################################################################

# Function for writing log file
def writeLog(function, message):
   
    currentTime = time.asctime()

    # Determines severity of log entry based on the message
    log_level = "ERROR" if "error" in message.lower() else "INFO"
    
    # Define fixed widths for each section of log entry
    log_level_width = 6  # e.g., "ERROR |"
    timestamp_width = 26 # e.g., "Tue Oct 10 08:05:00 2023 |"
    function_width = 15  # e.g., "| KEY CREATION |"
    
    log_entry = f"{log_level:<{log_level_width}} | {currentTime:^{timestamp_width}} | {function:^{function_width}} | {message}\n"

    with open(maindir + "/Logs/malEncryptLog", "a+") as log:
            log.write(log_entry)
    
    # functions: DELETE KEY | GENERATE KEY | DECRYPT | ENCRYPT
    # writeLog("FUNCTION", "MESSAGE")


#####################################################################################################################


main()
