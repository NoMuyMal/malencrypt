                                    WELCOME TO MALENCRYPT 2.0 by NOMUYMAL


THE ALL IN ONE ENCRYPTING SERVICE FOR LINUX DIRECTORIES USING AES128.
RUN THE SCRIPT IN ANY DIRECTORY YOU WANT TO ENCRYPT OR DECRYPT
SEE PROGRAM RUNDOWN FOR MORE INFORMATION.


GENERAL INFORMATION:

WITH OVER 500 MORE LINES OF CODE, THERE IS MUCH MORE FUNCTIONALITY TO EXPOLORE! 

This application allows users to create and manange encryption keys to then encrypt and decrypt entire directories.
Directories are encrypted with a password, which is hashed with SHA256, encrypted with AES128, then saved in the user's documents folder.

EVERY FILE -- KEYS, PASSWORDS, LOGS --  ARE STORED IN THE USERS DOCUMENTS DIRECTORY (~/Documents/malEncrypt/).
ONLY THE CURRENT USER IS GRANTED ACCESS TO THE DIRECTORY AND ITS FILES.

Typing "q" at anytime during the program's execution will quit the current function.


PROGRAM RUNDOWN:

Program is designed to operate in either a signle or multi-user environment.
Each user can create and delete their own set of keys to encrypt and decrypt directories.
The program will attempt to encrypt all files in the same directory which the script is run.
Before running other funcitons, users select a AES128 key created when first running the script. 


Encryption Function:

    Encrypting a directory will save an user inputted password, hashed with SHA256. 
    This password will be used for authentication to decrypt the directory later.

    Each file in the directory will be encrypted with AES128 symmetric encryption.
    Program will not encrypt the program itself or files with no permissions granted. 
    The proram can be run multiple times on the same directory for multiple layers of encryption.


Decryption Function:

    When decrypting, the program will search for saved passwords relating to the current directory.
    If none are found, user is given a choice of passwords which relate to the chosen key.

    If program is able to decrypt a password with the user's chosen key, the user will 
    be prompted to enter the password.
    When the user types the password in correctly, the decryption process begins.
    If password is incorrect too many times, the program will pause for a number of seconds
    before user can try again.

    Once files are decrypted successfully, the program will delete the used password.
    If there is an error decrypting any of the files, the password will be saved until user recovers their files. 


BE CAREFUL:

Removing or modifying any password or key files might cause encrypted data to be unrecoverable.

Modifying any files already encrypted might cause errors when decrypting.

Logs are saved for each user for audditing and debugging purposes.
