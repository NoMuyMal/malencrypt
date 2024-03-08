#
# VERSION 2.2.6
# UPDATED 3/8/2024 12:00 CDT
#
# Program used to encrypt files in a Linux directory with AES 128 symmetric encryption
# Users manage their own keys and passwords to encrypt files for decryption later
# Look at README for more information
# BUILT TO BE USED IN LINUX ONLY
#
#! TEST IF WINDOWS COMPATIBLE

try:
    from cryptography.fernet import Fernet
    from cryptography.fernet import InvalidToken

except ModuleNotFoundError:
    print("Install cryptography with 'pip install cryptography'")
    exit()

from pathlib import Path
import getpass
import hashlib
import os
import platform
import sys
import time


print(f'\n{"WELCOME TO MALENCRYPT":^64}')


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

    # Prints when user first runs the program
    print(f'\n{"Begin by creating a key that can be used to encrypt":^64}')
    print(f'{"or decrypt a directory of your choice at any time.":^64}')
    print(f'\n{"Refer to the READ.ME for more information.":^64}\n\n')
    
if not os.path.isdir(maindir + "/Passwords/"):
    os.mkdir(maindir + "/Passwords/")
    os.chmod(maindir + "/Passwords/" , 0o700)

if not os.path.isdir(maindir + "/Logs/"):
    os.mkdir(maindir + "/Logs/")
    os.chmod(maindir + "/Logs/" , 0o700)

    with open(maindir + "/Logs/malEncryptLog", "a+") as log:
        log.write("                  BEGINNING OF MALENCRYPT LOG               \n")
        log.write(f"{'TIME':^26} | {'FUNCTION':^15} | {'TYPE':^7} | {'MESSAGE'}\n")


###+++---

# Function to kick off program and let user select other functions
def main():
    
    print(f'{"Enter one of the letters below to run a command":^63}\n')
    
    if platform.system() != "Linux":
        print("This script is only runnable on Linux!\n")
        return

    # While loop to capture user input on what operation to run
    selection = ""
    while True:
        
        selection = input(str("(E)Encrypt | (D)Decrpyt | (C)Create or (R)Remove Key | (Q)Quit: " ))

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
            break

        # elif selection.lower() == "t":
        #     test()
        #     break

        else:
            print(selection, "is not a valid entry. Please try again \n")


###+++---

# Function to encrypt all files in current directory with user chosen key
# User inputs password that is saved for decrypt function later
def encrypt():

    if countKeys() <= 0:
        print(f'\n{"No key has been created for this user yet.":^63}\n')
        return

    # getDirectory returns user chosen directory and its base directory
    chosenDir, dirBaseName = getDirectory("encrypt")
 
    # If user decides to quit during directory selection
    if chosenDir == 'q':
        print()
        return

    # Method returns a valid created key chosen by user
    keyPath, keyName = validateKey()

    # If user decides to quit during key selection
    if keyPath == 'q':
        print()
        return
    
    print(f'\n{f"Encrypting directory:":^64}')
    print(f"{str(chosenDir):^64}")
    
    # While loop for creating valid password
    while True: 
        password = getpass.getpass(str("\nPlease enter a password for later decryption: ")).encode()

    # If user wants to quit or if password length is too short are handled here
        if password.lower() == 'q'.encode():
            print(f"\n\n{'Cancelling encryption.':^63}\n\n")
            return

        if len(password) < 3:
            print("Password must be at least 3 characters. Please try again.")
            continue

        confirmPass = getpass.getpass(str("Enter the same password again to confirm: ")).encode()
        print()
        
    # While loop is broken if users confirms password is correct
        if password == confirmPass:
            break
        else:
            print("Passwords do not match. Please try again.")

    SHA256 = hashlib.new("SHA256") # SHA256 object created 
    SHA256.update(password) # Creates hash digest of password to save

    # Opening key file to encrypt password and files
    with open(keyPath, "rb") as keyFile:
        key = keyFile.read()

    # passwordLocation variable saves password in format: ~/Documents/malEncrypt/Passwords/key_directory_Password
        passwordLocation = maindir + "/Passwords/" + keyName.replace(".key","") + "_" + \
                            str(dirBaseName) + "_password"

    # If any file in saved passwords includes current directory, user is informed
        cont = 'yes'                    
        for passwordFile in os.listdir(maindir + "/Passwords/"):
            if dirBaseName in passwordFile:

                print(f"{'The directory you are trying to encrypt':^48}")
                print(f"{'might have been encrypted at least once already.':^48}")
                
                cont = input(f"{'Are you sure you want to continue (yes or no)?':^48}\n")
                print()
                break

        if cont[0].lower() != 'y':
            print(f"{'Cancelling encryption.':^63}\n")
            return

        # Counter used to add digits to the end of password file name to mitigate overwriting passwords
        counter = 2 

    # While loop to change a password's name incase a duplicate password exists    
        while os.path.isfile(passwordLocation):
        
        # If no number is after password file name, 2 is added to the
        #  end of the name. e.g. key_dir_password2
            if passwordLocation[-1] == 'd':
                passwordLocation = passwordLocation + '2'
      
        # If pasword name already has number, the counter counts up until new
        #   number is found to replace old number. e.g. key_dir_password3
            elif passwordLocation[-1] != str(counter):
                passwordLocation = passwordLocation[:-1] + str(counter)

            counter += 1

    # Saving encrypted digest of password entered
        with open(passwordLocation, "wb") as passwordFile:
            passwordFile.write(Fernet(key).encrypt(SHA256.hexdigest().encode()))

            os.chmod(passwordLocation , 0o600) # Edits perms for only current user to access
            writeLog("ENCRYPT", f"{passwordLocation.replace(maindir + '/Passwords/', '')} was saved")

    # gatherFiles returns and validates every file in chosen directory
        files = gatherFiles(chosenDir)

    # Encrypting each file returned by gatherFiles()
        for file in files:      

            with open(file, "rb") as theFile:
                contents = theFile.read()
                contentsEncrypted = Fernet(key).encrypt(contents)

            with open(file, "wb") as theFile:
                theFile.write(contentsEncrypted)

        print(f"\n{'Your files have been encrypted!':^64}\n\n")
        writeLog("ENCRYPT", f"{str(chosenDir)} directory was encrypted with {keyName}.key")


###+++---

# Function to decrypt all files in current directory with user chosen key
# User inputs correct password to decrypt the files
def decrypt():

    if countKeys() <= 0:
        print(f'\n{"No key has been created for this user yet.":^63}\n')
        return
    
    # getDirectory returns user chosen directory and its base directory
    chosenDir, dirBaseName = getDirectory("decrypt")

    # If user decides to quit during directory selection
    if chosenDir == 'q':
        print()
        return

    # Method returns a valid key chosen by user
    keyPath, keyName = validateKey()

    # If user decides to quit during key selection
    if keyPath == 'q':
        print()
        return

    print(f'\n{f"Decrypting directory:":^64}')
    print(f"{str(chosenDir):^64}")

    # Key will be opened for later decryption
    with open(keyPath, "rb") as key:
        openedKey = key.read()

    passwordList = [] # Initialized list for passwords to be chosen by program for decryption

    # Password naming scheme: key_directory_Password
    # Gathers available passwords with the current directory in then name for possible decryption
    for item in os.listdir(maindir + "/Passwords/"):
        if dirBaseName in item:
            passwordList.append(item)
    
    passwDecryptSuccess = False # Initialize bool for password selection

    # Each password will try to be decrypted until there is a success
    for password in passwordList:
        with open(maindir + "/Passwords/" + password) as currentPassword:
            openedPassword = currentPassword.read()
            
            try: 
                decrpytedPassword = Fernet(openedKey).decrypt(openedPassword)
                
            # Password decrypted successfully if exception not thrown
                passwDecryptSuccess = True
                correctPasswordPath = maindir + "/Passwords/" + password
                break
            
            except InvalidToken: # raises when key does not match with encrypted password
                continue
    
    # If no password was able to be decrypted previously, program will find all passwords with the key name to give user a selection
    if passwDecryptSuccess == False:
        passwordList = []
        passwordList = [item for item in os.listdir(maindir + "/Passwords/") if keyName in item]
    
    # If there is no match in key name or directory, program has no password to decrypt.
        if passwordList == []:
            print(f'\n{"There is nothing to decrypt with this key!":^64}')
            print(f'{"Make sure you selected the correct key.":^64}\n')
            return

        print("\nPassword for this directory not found! If the directory's name changed, select password with the previous name.")
        print("            Please type the name of the password you want to choose below or type 'q' to cancel.\n")
        # print(*passwordList , "\n")
       
        lengthCondition = 79  
        passwords = ""

        for item in passwordList:

        # Format output looks like: |  key1  |  key2  |  etc... |
            passwords += "  |  " + item + "  |" # formats output for each key

            # A new line is generated every 60 characters
            if len(passwords) > lengthCondition:
                passwords += "\n"
                lengthCondition += 79

        print(passwords)




    # While loop for taking valid password input
        while True:
            password = input()
            
            if password in passwordList:
                break
            if password.lower() == 'q':
                print(f"\n\n{'Cancelling decryption.':^63}\n\n")
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
            except InvalidToken:
                print(f"\n{f'{keyName} is not the correct key for {password}':^64}\n")
                writeLog("DECRYPTION", f"Error decrypting {password} with {keyName}.key for directory {str(chosenDir)}")
                return


    # If a password is decrypted successfully, the program will begin to decrypt files
    if passwDecryptSuccess:

        # Gets user's input to compare password hashes
            inputPassword = getpass.getpass(str("\nInput a password to decrypt your files: ")).encode()

        # If user wants to quit decrypting
            if inputPassword.lower() == "q".encode():
                print(f"\n\n{'Cancelling decryption.':^63}\n\n")
                return
    
            SHA256 = hashlib.new("SHA256") # create hash function for password
            SHA256.update(inputPassword)

            counter = 0 # Initialized to count number of failed password entries

        # While loop until user enters correct password before decrypting
            while True:

            # If the digest of inpputed password is equal to the digest of the saved password decrypting begins
                if SHA256.hexdigest().encode() == decrpytedPassword:

                    files = gatherFiles(chosenDir) # gathers list of files from chosen directory

                    decryptError = False # Initialized for error decrypting any files later
                    print()

                # Decrypting files in chosen directory
                    for file in files:
                        with open(file, "rb") as currentFile:
                            contents = currentFile.read()
                            
                        # If there is an error decrypting a file, user will be warned and error will be noted
                            try:
                                decryptedContents = Fernet(openedKey).decrypt(contents)
                            except:
                                print(f"\n{f'  !! Error decrypting file: {file.name} !!':^64}\n")
                                writeLog("DECRYPTION", f"Error decrypting file: {file} with {keyName}.key")
                                decryptError = True
                                continue
                            
                        with open(file, "wb") as currentFile:
                            currentFile.write(decryptedContents)

                
                    if decryptError:
                        print(f"\n{f'Any other files were decrypted successfully.':^64}")
                        print(f"{f'Please check logs for more information.':^64}\n")

                    # Saves password for debugging and writes error to log
                        if "debug" not in password:
                            debugPasswordPath = maindir + "/Passwords/" + password + "_debug"
                        else:
                            debugPasswordPath = maindir + "/Passwords/" + password

                        os.replace(correctPasswordPath, debugPasswordPath)
                        writeLog("DECRYPTION", f"Error while decrypting {str(chosenDir)} with {keyName}.key, saving password: {debugPasswordPath}")
              
                # If there is no error, used password will be deleted  
                    else:
                        print(f"\n{'All files decrypted successfully!':^64}\n\n")
                        os.unlink(correctPasswordPath) # deletes password file after decryption
                        
                        writeLog("DECRYPTION", f"{password} was used successfully and deleted.")
                        writeLog("DECRYPTION", f"{str(chosenDir)} was decrypted successfully with {keyName}.key")

                    break
            
            # Runs if user inputted the incorrect password #! do something about script restarting
                else:

                # Incase user wants to quit
                    if inputPassword.lower() == "q".encode():
                        print(f"\n\n{'Cancelling decryption.':^63}\n\n")
                        return

                    counter += 1
                    if counter >= 4: 
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
        writeLog("DECRYPTION", f"{keyName}.key was not able to decrypt any passwords for directory {str(chosenDir)}")


###+++---

# Fucntion for used to create new keys for user to encrypt/decrypt with
def keyGen():
    
    print("\nInsert a name for the key you want to create or 'L' for list of existing keys: ")
    keyPath, keyName = getKeyName()

    # Key must be alphanumeric and 3 characters long
    while (len(keyName) < 3 or not keyName.isalnum()) and keyPath != "q":
        print("\nPlease enter at least three characters for the key name with no special characters:")
        keyPath, keyName = getKeyName()

    if keyPath.lower() == 'q':
        print()
        return

    if os.path.isfile(keyPath): # triggers if key with the same name is already generated (prints in red)
            print("\033[91m {}\033[00m" \
            .format(f"\n{'There is already a key generated with the same name.':^84}\n" \
            f"{'Continuing will overwrite this key causing encrypted files to never be decrypted.':^84}\n"))
            
            print(f"\n{'Are you sure you want to continue (yes or no)?':^84}")
            warning = input(str(""))
        
            while True:
                
                if warning.lower() == "yes":
                    print()
                    writeLog("GENERATE KEY", f"{keyName}.key was overwritten!")
                    break

                elif warning.lower() == "no":
                    print(f"\n{'Cancelling. Key was not overwritten.':^63}\n")
                    return
                
                else:
                    warning = input(str("Invalid input, please type 'yes' or 'no': ")) 

    key = Fernet.generate_key() # generates AES key 128 bit

    with open(keyPath, "wb") as theKey: # saves key file
        theKey.write(key)
        
    os.chmod(keyPath, 0o700) # only current user has perms on key file

    print()
    print(f'\n{f"{keyName} key has been created!":^64}\n\n') 
    writeLog("CREATE KEY", f"{keyName}.key created")


###+++---

# Funciton for user to delete keys no longer needed
def removeKey():

    # Variable determines if user wants to continue with deleting key
    cont = 'no'

    if countKeys() <= 0:
        print(f'\n{"No key has been created for this user yet.":^63}\n')
        return

    keyPath, keyName = validateKey()

    if keyPath.lower() == 'q':
        print()
        return


    # If password file has keyname in it, there is still files encrypted with that key
    for file in os.listdir(maindir + "/Passwords/"):
        if keyName in file:
            print()
            print(f"{'There are files encrypted with this key still':^64}")
            print(f"{'Deleting the key will cause these files to be unrecoverable':^64}")
            break

    # Even if there are no files encrypted with key, still asking if user wants to delete key
    print(f"\n{f'Are you sure you want to delete the {keyName} key (yes or no)?  ':^64}")
    cont = input(str(""))


    if cont.lower() == 'yes':
        os.unlink(keyPath)
        print(f'\n\n{f"{keyName}.key has been deleted.":^64}\n\n')
        writeLog("REMOVE KEY", f"{keyName}.key deleted")
    else:
        print(f'\n\n{f"No key was deleted.":^64}\n\n')


###+++---

# Function for gathering user input when function asks user to select key
# e.g. user selecting a key to encrypt with

def getKeyName():

    # While loop to let user select a key after listing them
    while True:

        keyName = input(str())

        # List all keys if user entered 'l'
        if keyName.lower() == 'l':

        # Method returns true if keys have been created
            if countKeys() <= 0:
                print("\nNo keys generated yet. Please enter a name of a key to generate: ")
            else:
                print()

            # Variables defined and ready to list keys
                keys = ""
                maindirList = os.listdir(maindir)
                maindirList.sort()       
                lengthCondition = 60  

                for item in maindirList:

                # Format output looks like: |  key1  |  key2  |  etc... |
                    if ".key" in item:
                         keys += "  |  " + item.replace(".key", "") + "  |" # formats output for each key

                    # A new line is generated every 60 characters
                         if len(keys) > lengthCondition:
                            keys += "\n"
                            lengthCondition += 60

                print(keys)
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


###+++---

# Function used to gather files for encryption or decrpytion
def gatherFiles(chosenDir):

    # List initialized to collect all files within a directory
    files = []

    scriptName = os.path.basename(sys.argv[0])

    for file in os.listdir(chosenDir): # adds files to list except for script and directories

        file = chosenDir / file

    # These files are not added to the list
        if file == chosenDir / scriptName: # if file == name of script 
            continue
        if os.path.isdir(file):
            continue
        if file in files: # makes sure there are no duplicate files
            continue

    # If user does not have perms for file, it is skipped
        if not os.access(file, os.R_OK):

            if not os.access(file, os.W_OK):
                print(f"\nNo read or write permissions greanted to file: {file.name}")
                continue
            else:
                print(f"\nNo read permissions greanted to file: {file.name}")
                continue

        if not os.access(file, os.W_OK):
            print(f"\nNo write permissions greanted to file: {file.name}")
            continue

    # File is appended if passes validation
        files.append(file) 
    
    return files


###+++---

# Counts number of keys created by a user 
def countKeys():
    
    numKeys = 0
    
    for item in os.listdir(maindir):
        if ".key" in item:
            numKeys += 1

    return numKeys

###+++---

# Determines actions based on how many keys are generated by user & lets user select valid key
def validateKey():

    numKeys = countKeys()

    if numKeys == 0:
        print(f'\n{"No key has been created for this user yet.":^63}')
        return "q", ""

    # If only one key has been created, that key is automatically selected.
    if numKeys == 1:
        for item in os.listdir(maindir):
            if ".key" in item:
                keyName = item.replace(".key", "")
                keyPath = maindir + "/" + item
                print(f'\n{"%s key has been selected automatically." % keyName:^64}') 
                
    else:
        
    # If there are multiple keys, user must select a correct key
        print("\nInsert a name for the key you want to encrypt with or 'L' for list of existing keys: ")
        keyPath, keyName = getKeyName()

     # Makes sure user selects a valid key
        while keyName + ".key" not in os.listdir(maindir) and keyPath != "q":
            print("\nKey not found. The selection is case sensitive. Please try again: ")
            keyPath, keyName = getKeyName()
    
        if keyPath == "q":
            return "q", ""

        print(f'\n\n{"%s key has been selected." % keyName:^64}')

    return keyPath, keyName

###+++---

# Function for writing to log file
def writeLog(action, message):
   
    currentTime = time.asctime()

    # Determines severity of log entry based on the message
    if "error" in message.lower():
        log_level = "ERROR"
    
    elif "debug" in message.lower():
        log_level = "DEBUG"

    else:
        log_level = "INFO"




  # e.g.,  Tue Oct 10 08:05:00 2023 | KEY CREATION | ERROR | MESSAGE...
    log_entry = f"{currentTime:^26} | {action:^15} | {log_level:^7} | {message}\n"

    with open(maindir + "/Logs/malEncryptLog", "a+") as log:
            log.write(log_entry)
    
    # Actions:
    #    REMOVE KEY | GENERATE KEY | DECRYPTION | ENCRYPT


###+++---

# Function allows user to choose directory when encrypting or decrypting
# Mode parameter is either encrypt when encrypting or decrypt when decrypting
# User should be able to select a file, then choose multiple files

def getDirectory(mode):
    #! USING DIR DOT NOTATION WORKS SOMEWHAT AND DOESNT LOOK GOOD IN LOGS
    while True:

        inputDir = input(f"\nPlease select a directory to {mode} (enter for cwd):\n")

        # If user wants to quit and there is no directory named "q" in cwd
        if inputDir == "q" and not os.path.isdir(os.getcwd() + "/" + "q"):
            return "q", ""
        
        # If user pressed enter, program chooses current working directory
        if inputDir == "":
            inputDir = os.getcwd()
            break
        
        # Input validation to make sure inputDir is actual directory
        if "." in inputDir:
            print("\nDot notation is not supported yet.")
            continue
        
        if os.path.isdir(os.getcwd() + "/" + inputDir) and inputDir[0] != "/":
            inputDir = os.getcwd() + "/" + inputDir
            break

        if not os.path.isdir(inputDir):
            print("\nNot a valid directory!")
            continue
        
        # Checks if user has access to chosen directory
        if not os.access(inputDir, os.R_OK) or not os.access(inputDir, os.W_OK):
            print("\nNo permissions to chosen directory.")
            continue
    
        break

    # Adds slash if user did not already
    if inputDir[-1] != "/":
        inputDir += "/"

    # Creates pathlib object
    dirPath = Path(inputDir)

    # Gives the name of directory that will be encrypted
    dirBaseName = dirPath.name

    return dirPath, dirBaseName


###+++---

def test():
    print("Nothing to test!")


###+++---

# Calling main function for user to select functions
if __name__ == "__main__":
    main()

