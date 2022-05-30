Readme file for End of Module Assignment

The code is written in Python.

Overview of the solution
The purpose of the code is to provide access to a secure database. 
In order to achieve this, Multi-Factor Authentication/2-Factor Authentication has been implemented, alongside the use of a username and password combination, that is required to access the ASMIS database.
In addition, the password stored in the database, is hashed for additional security.
3 python libraries (Colab, 2022) were required for this program – 

The database was created using the sqlite3 (Sqlite3) library. Sqlite3 (Tutorialspoint, ND) allows for the creation of a database using the SQL form, and allows for the database to integrate with Python.Sqlite3 is part of the python standard libraries, but it must be imported before use.

Bcrypt (Bcrypt) is a password hashing algorithm (Zetcode, 2021). It is used to encrypt and decrypt a password, but the password is stored in the database as a hashed value for additional security.

Pyotp (Pyotp) is a library used to generate and verify the use of one-time passwords (2FA, 2021), (programcreek, ND). These passwords are time based, and must be generated separately, every time the user tries to login.

How to use the program
The code is written in 2 parts – Implementation Code and Verification Code.

**
**Implementation Code**
**

Begin by installing and importing the 3 required libraries. Ensure that they load properly.
Next, create the Sqlite3 Database, and define a table with columns.

In the code, the table is created with 4 columns, but only the username and password columns will be used at this stage.
The username column is set to be UNIQUE, meaning that each user needs their own individual username. The password field is hashed, and cannot be read by anyone that has access to the database, without first decrypting the password.

In a real-world scenario, the password field will be dynamically filled and hashed, when the patient first creates or alters their login.
In this case, we must first manually define the hashed key, for the static passwords that will be used on our 4 test accounts.
Passwords are entered in plain text, and then using bcrypt, a hashed value is created for all 4 passwords. This hashed value is unique, and is different every time the algorithm is run.
After each hashing algorithm code section, there is the option to verify that the clear text password and the hashed values match.

After we have obtained the hashed values for the passwords, we need to modify the records(following) for the test users, by inserting the unique hash values into the password field.
Once completed, we can then create and add the 4 patient records to the database.

**
**Verification Code**
**

The first verification field in the code, is used to check that the table in the database was created to only allow unique usernames. 
A second record with a duplicate username will not be added.

There are now 2 processes, repeated 4 times, one repetition for each user.
The first process is to manually input the username and password combination for a patient record (1st factor authentication), and then to generate a One-Time password (2nd factor authentication) to be used in combination, to authenticate and login to the ASMIS database.
As the process runs, it validates the password, and if correct, it generates a new OTP that is then displayed.
The next part of the code is used to enter the freshly created OTP, and to validate the authentication process. At this point, the user will receive a message that they are authenticated or not.

(600 words)

Libraries:
SQLITE3 - https://docs.python.org/3/library/sqlite3.html
BCRYPT - https://pypi.org/project/bcrypt/
PYOTP - https://pypi.org/project/pyotp/

References:
Colab (2022) via email. CS Examples for EMA. Available from: https://colab.research.google.com/drive/1B72_kiRMeEoa98ir4eHPPC7mjMVVOu8x?usp=sharing [Accessed 28 May 2022].

Tutorialspoint (ND). SQLite – Python. Available from:
https://www.tutorialspoint.com/sqlite/sqlite_python.htm [Accessed 28 May 2022].

2FA (2021). 2FA One Time Passwords mit PYOTP Python. Available from:
https://www.youtube.com/watch?v=sj03Q-JYZqA [Accessed 28 May 2022]. (In German)

Programcreek (N.D).Python.random_base32() Examples. Available from:
https://www.programcreek.com/python/example/127972/pyotp.random_base32 [Accessed 28 May 2022].

Zetcode (2021). Python bcrypt. Available from:
https://zetcode.com/python/bcrypt/  [Accessed 28 May 2022].



