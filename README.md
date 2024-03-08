                                    WELCOME TO MALENCRYPT 2.0 by NOMUYMAL


THE ALL IN ONE ENCRYPTING SERVICE FOR LINUX DIRECTORIES USING AES128.
RUN THE SCRIPT TO ENCRYPT OR DECRYPT ANY DIRECTORY OF YOUR CHOICE
SEE PROGRAM RUNDOWN FOR MORE INFORMATION.


PROGRAM RUNDOWN:

Program is designed to operate in either a signle or multi-user environment.
Each user can create and delete their own set of AES128 keys to encrypt and decrypt directories of their choice.

The program will attempt to encrypt all files in directory excluding the script itself or files without permissions.

When first running the script, user must create a key before running any other functions

Program does not affect further directories in the tree, only the selected directory.


Encryption Function:

    Encrypting a directory will save a password the user inputs, hashed with SHA256. 
    This password will be used for authentication to decrypt the directory later.

    Each file in the directory will be encrypted with AES128 symmetric encryption.
    The proram can be run multiple times on the same directory for multiple layers of encryption.
    Program will not encrypt the program itself or files with no permissions granted. 


Decryption Function:

    When decrypting, the program will search for  passwords saved for the current directory.
    If none are found, user is given a choice of passwords which were saved for the chosen key.

    If program is able to decrypt a password with the user's chosen key, the user will 
    be prompted to enter the password.

    When the user types the password in correctly, the decryption process begins.

    Once files are decrypted successfully, the program will delete the used password.
    If there is an error decrypting any of the files, the password will be saved until user recovers their files. 



GENERAL INFORMATION:


This application allows users to create and manange encryption keys to then encrypt and decrypt entire directories.

Script will not encrpyt files in the entire directory tree, only files in the directory chosen.

Directories are encrypted with a password, which is hashed with SHA256, encrypted with AES128, then saved in the user's documents folder.


EVERY FILE -- KEYS, PASSWORDS, LOGS --  ARE STORED IN THE USERS DOCUMENTS DIRECTORY (~/Documents/malEncrypt/).

ONLY THE CURRENT USER IS GRANTED ACCESS TO THIS DIRECTORY AND ANY OF ITS FILES.


This script is meant to encrypt data at rest; if you wanted to transport encrpyted files, the recipeint will also need

this script and the password file on their system in order to decrypt.

Typing "q" at anytime during the program's execution will quit the current function.



BE CAREFUL:


Removing or modifying any password or key files might cause encrypted data to be unrecoverable.

Modifying any files already encrypted might cause errors when decrypting.

Logs are saved for each user for auditing and debugging purposes.

