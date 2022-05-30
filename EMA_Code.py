
#**IMPLEMENTATION CODE**


# add sqlite library
import sqlite3

# add PYOTP library
!pip install pyotp
import pyotp

# add bcrypt library
!pip install bcrypt
import bcrypt

#create base SQL DB
connection = sqlite3.connect("asmis_db")
cursor = connection.cursor()
#create table called "users" in test_db database - username must be a unique field
cursor.execute("CREATE TABLE users (username VARCHAR(25) UNIQUE, city VARCHAR(20), age INTEGER, password VARCHAR(20)) ")

#Unmodified Username/Password combinations before Passwords are hashed - Kasia 123456, Mary 654321, Viktoria abcdef, Winnie fedcba
#hashed value changes everytime the algorithm runs
# In many cases, it wass necessary to re-import either bcrypt or pyotp before the relevant commands.
# This should not be necessary, and is believed to be related to colab rather than Python itself.



# Perform hashing algorithm on password for User: Kasia
import bcrypt
password = b"123456"

salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password,salt)

print(salt)
print(hashed)

#Code used to verify hashed password for User:Kasia
import bcrypt
password = b'123456'
if bcrypt.checkpw(password,hashed):
  print("You have a match")
else:
  print("Password does not match")

# Perform hashing algorithm on password for User: Mary
import bcrypt

password = b"654321"

salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password,salt)

print(salt)
print(hashed)

#Code used to verify hashed password for User: Mary
import bcrypt
password = b'654321'

if bcrypt.checkpw(password,hashed):
  print("You have a match")
else:
  print("Password does not match")

# Perform hashing algorithm on password for User: Viktoria
import bcrypt

password = b"abcdef"

salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password,salt)

print(salt)
print(hashed)

#Code used to verify hashed password for User: Viktoria
import bcrypt
password = b'abcdef'

if bcrypt.checkpw(password,hashed):
  print("You have a match")
else:
  print("Password does not match")

# Perform hashing algorithm on password for User: Winnie
import bcrypt

password = b"fedcba"

salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password,salt)

print(salt)
print(hashed)

#Code used to verify hashed password for User: Winnie
import bcrypt
password = b'fedcba'

if bcrypt.checkpw(password,hashed):
  print("You have a match")
else:
  print("Password does not match")

#Add records to database with already hashed password
#Passwords stored in database encrypted, for additional security
cursor.execute("INSERT INTO users VALUES ('Kasia', 'kracow', 30, '$2b$12$oZnAh/hQBOejxOCE/KvfAe2XtqVERjcVdPEbnvSpv4gE.vXz16hQe') ")
cursor.execute("INSERT INTO users VALUES ('Viktoria', 'Dublin', 30, '$2b$12$3oSJV3Ojks/CCvoOENbwqe3jWQdIkNNZoZzuyWOkV0NASUsT3y.0K') ")
cursor.execute("INSERT INTO users VALUES ('Mary', 'Galway', 28, '$2b$12$W0KIQncronYfpuZWZr8g/uWA67rtLFCn2li/xYaRM02mb0P9eJYbm') ")
cursor.execute("INSERT INTO users VALUES ('Winnie', 'Werfen', 60, '$2b$12$Uoy3C0vNUuMkMqk1yOuRZOB8NBmX3Ns24NhqI9PKYLQmr75GRuu7u') ")

#**VERIFICATION CODE**

#Verify uniqueness of username field


cursor.execute("INSERT INTO users VALUES ('Winnie', 'Linz', 27, '$2b$12$U0fltka1nj02yLwrJP5bbe8vdgfdgfgdfgfdg7W3kPde3.fFDye') ")
print()
# addition of user account with same name as existing record will fail

#Individual testing and verification of 4 user accounts in the database

username = "Kasia"
password = "123456"
#Password is unencrypted text

statement = f"SELECT username from users WHERE username='{username}' AND Password = '{password}';"
cursor.execute(statement)
#
import pyotp
# Code fails most times without reimporting pyotp again here
#
# Generate time-based One Time Password
totp = pyotp.TOTP('base32secret3232')
#Display TOTP on screen
print("Your OTP is:",totp.now())

# Enter generated TOTP for authentication
if totp.verify('519544')==True:
  print("Login Successful")
else:
 print("Access Denied")

username = "Viktoria"
password = "abcdef"
#Password is unencrypted text

statement = f"SELECT username from users WHERE username='{username}' AND Password = '{password}';"
cursor.execute(statement)
#
import pyotp
# Code fails most times without reimporting pyotp again here
#
# Generate time-based One Time Password
totp = pyotp.TOTP('base32secret3232')
#Display TOTP on screen
print("Your OTP is:",totp.now())

# Enter generated TOTP for authentication
if totp.verify('621390')==True:
  print("Login Successful")
else:
 print("Access Denied")

username = "Mary"
password = "654321"
#Password is unencrypted text

statement = f"SELECT username from users WHERE username='{username}' AND Password = '{password}';"
cursor.execute(statement)
#
import pyotp
# Code fails most times without reimporting pyotp again here
#
# Generate time-based One Time Password
totp = pyotp.TOTP('base32secret3232')
#Display TOTP on screen
print("Your OTP is:",totp.now())
#
#

# Enter generated TOTP for authentication
if totp.verify('771784')==True:
  print("Login Successful")
else:
 print("Access Denied")

username = "Winnie"
password = "fedcba"
#Password is unencrypted text

statement = f"SELECT username from users WHERE username='{username}' AND Password = '{password}';"
cursor.execute(statement)
#
import pyotp
# Code fails most times without reimporting pyotp again here
#
# Generate time-based One Time Password
totp = pyotp.TOTP('base32secret3232')
#Display TOTP on screen
print("Your OTP is:",totp.now())
#
#

# Enter generated TOTP for authentication
if totp.verify('730779')==True:
  print("Login Successful")
else:
 print("Access Denied")
