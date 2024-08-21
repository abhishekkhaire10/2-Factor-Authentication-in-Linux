import os
import subprocess
import sys
import re
from passlib.hash import sha512_crypt
import crypt
import spwd  # To safely handle /etc/shadow
import getpass

class User:
    def __init__(self, username, password, salt):

        # Check if the user already exists during object creation
        if self.user_exists(username):
            print("The user already exists. Try deleting it first.")
            sys.exit()
            

        self.username = username
        self.password = password
        self.salt = salt
        self.hashed_password = sha512_crypt.hash(password, salt_size=8, salt=salt, rounds=5000)

        # Add the user to the OS
        self.update_passwd_file()
        self.update_shadow_file()
        self.create_home_directory()


    def get_hashed_password(self):
        return self.hashed_password

    def set_hashed_password(self, password, salt):
        self.self.hashed_password = sha512_crypt.hash(password, salt_size=8, salt=salt, rounds=5000)

    def get_username(self):
        return self.username

    def get_password(self):
        return self.password

    def set_password(self, new_password):
        self.password = new_password

    def get_salt(self):
        return self.salt

    def set_salt(self, new_salt):
        self.salt = new_salt

    @staticmethod
    def user_exists(username):
        with open(SHADOW_FILE, 'r') as fp:
            for line in fp:
                if line.startswith(username + ":"):
                    return True
        with open(PASSWD_FILE, 'r') as fp:
            for line in fp:
                if line.startswith(username + ":"):
                    return True
        return False

    def update_passwd_file(self):
        count = 1000

        with open(PASSWD_FILE, 'r') as f:
            for line in f:
                temp1 = line.split(':')
                while count <= int(temp1[3]) < 65534:
                    count = int(temp1[3]) + 1
        count = str(count)

        passwd_line = f"{self.username}:x:{count}:{count}:,,,:/home/{self.username}:/bin/bash"

        with open(PASSWD_FILE, 'a+') as passwd_file:
            passwd_file.write(passwd_line + '\n')

    def update_shadow_file(self):
        shadow_line = f"{self.username}:{self.hashed_password}:17710:0:99999:7:::"
        with open(SHADOW_FILE, 'a+') as shadow_file:
            shadow_file.write(shadow_line + '\n')

    def create_home_directory(self):
        try:
            os.mkdir("/home/" + self.username)
        except FileExistsError:
            print("Directory: /home/" + self.username + " already exists")

    def __str__(self):
        return (f"Username:\t{self.username}\nPassword:\t{self.password}\nSalt:\t\t{self.salt}\n"
                f"Hash:\t\t{self.hashed_password}")


# Constants for file paths
SHADOW_FILE = '/etc/shadow'
PASSWD_FILE = '/etc/passwd'


def check_root_privileges():
    """Check if the program is running with root privileges."""
    if os.getuid() != 0:
        print("Please run as root.")
        sys.exit()


def request_valid_salt():
    # Be aware that using a default salt for cryptographic purposes is not as secure as using a randomly
    # generated one. It's generally recommended to use a random salt for each user to enhance
    # the security of password hashing.
    # In our assignment we request the salt from the user for grading purposes.

    while True:
        user_input = request_input("Enter an 8-character salt (lowercase letters and digits)", "saltsalt")

        if re.match(r"^[a-z0-9]{8}$", user_input):
            return user_input
        else:
            print("Invalid salt. Please enter exactly 8 lowercase letters and digits.")
            retry = input("Do you want to retry? (yes/no): ")
            if retry.lower() != "yes":
                sys.exit("Exiting.")


def request_input(prompt, default=None):
    if default is not None:
        prompt += f" (or press Enter for {default}) : "
    response = input(prompt)
    if not response:
        return default
    return response

def create_user():
    username = input("Username: ")
    password = input("Password: ")
    confirm_password = input("Confirm Password: ")
    if password != confirm_password:
        print("FAILURE: Passwords do not match.")
        return
    salt = input("Salt: ")  
    initial_token = input("Initial Token: ")  

    # Check if the user already exists
    try:
        subprocess.run(["id", username], check=True, stdout=subprocess.DEVNULL)
        print(f"FAILURE: user {username} already exists")
        return
    except subprocess.CalledProcessError:
        # User doesn't exist, proceed to create
        pass
    hardened_password = password + initial_token
    hashed_password = sha512_crypt.hash(hardened_password, salt_size=8, salt=salt, rounds=5000)

    try:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", username], check=True)
        # Set the hashed password for the user
        subprocess.run(['usermod', '-p', hashed_password, username], check=True)
        print(f"SUCCESS: User {username} created with hashed password")
    except subprocess.CalledProcessError as e:
        print(f"Error creating user: {e}")
    
def login():
    username = input("Username: ")
    password = input("Password: ")
    current_token = input("Current Token: ")
    next_token = input("Next Token: ")

    # Concatenate password with current token to construct the hardened password
    hardened_password = password + current_token
     
    #print(hardened_password)
    #salt = "initial_salt_value"  # Initial value for demonstration

    with open('/etc/shadow', 'r') as f:
       
       for line in f:

        if line.startswith(username + ':'):
            parts = line.split('$')
            if len(parts) > 2:
                salt = parts[2]  # Update the salt variable
                break

    print(f" salt for {username}: {salt}")
    hashed_password=sha512_crypt.hash(hardened_password, salt_size=8, salt=salt, rounds=5000)


    # Validate against the hash value in the /etc/shadow file
    with open("/etc/shadow", "r") as shadow_file:
        for line in shadow_file:
            if line.startswith(username + ":"):
                hash_value = line.split(":")[1]
                print(hash_value)
                if hashed_password == hash_value:
                    print("SUCCESS: Password and current token validated.")
                    # Concatenate password with next token to create new hardened password
                    new_hardened_password = password + next_token
                    # Hash the new password
                    new_hashed_password = sha512_crypt.hash(new_hardened_password, salt_size=8, salt=salt, rounds=5000)
                    # Update the /etc/shadow file with the new hashed password
                    with open("/etc/shadow", "r") as shadow_file_read:
                        lines = shadow_file_read.readlines()
                    with open("/etc/shadow", "w") as shadow_file_write:
                        for line in lines:
                            if line.startswith(username + ":"):
                                shadow_file_write.write(f"{username}:{new_hashed_password}:{line.split(':')[2]}")
                            else:
                                shadow_file_write.write(line)
                    print("SUCCESS: New password updated in /etc/shadow.")
                    break
        else:
            print("FAILURE: Incorrect password or current token.")
        
def verify_password(username, hashed_password):
    try:
       with open("/etc/shadow", "r") as shadow_file:
        for line in shadow_file:
            if line.startswith(username + ":"):
                hash_value = line.split(":")[1]
                #print(hardened_password)
                print(hash_value)
        #password_hash = crypt.crypt(hardened_password, salt)
        return hashed_password == hash_value
    except KeyError:
        return False
    except PermissionError:
        print("Permission denied: Need root access to read /etc/shadow.")
        return False

def update_password():
    username = input("Username: ")
    current_password = input("Current Password: ")
    current_token = input ("Current token: ")
    with open('/etc/shadow', 'r') as f:
       
       for line in f:

        if line.startswith(username + ':'):
            parts = line.split('$')
            if len(parts) > 2:
                salt = parts[2]  # Update the salt variable
                break

        #print(f" salt for {username}: {salt}")

        #hashed_password = sha512_crypt.hash(current_password, salt_size=8, salt=salt, rounds=5000) 
    hardened_password = current_password + current_token
    # Concatenate current password with next token to create hardened password
    # hardened_password = current_password + current_token
    hashed_password = sha512_crypt.hash(hardened_password, salt_size=8, salt=salt, rounds=5000)
    if verify_password(username, hashed_password):
        new_password = input("New Password: ")
        confirm_new_password = input("Confirm New Password: ")
        next_token = input("Next token: ")
        if new_password != confirm_new_password:
            print("Error: New passwords do not match.")
            return
        new_hardened_password = new_password + next_token
                    # Hash the new password
        new_hashed_password = sha512_crypt.hash(new_hardened_password, salt_size=8, salt=salt, rounds=5000)
                    # Update the /etc/shadow file with the new hashed password
        with open("/etc/shadow", "r") as shadow_file_read:
                        lines = shadow_file_read.readlines()
        with open("/etc/shadow", "w") as shadow_file_write:
                        for line in lines:
                            if line.startswith(username + ":"):
                                shadow_file_write.write(f"{username}:{new_hashed_password}:{line.split(':')[2]}")
                            else:
                                shadow_file_write.write(line)
        print("SUCCESS: New password updated in /etc/shadow.")
        
    else:
            print("FAILURE: Incorrect password or current token.")

def delete_user_account():
    username = input("Username: ")
    password = input("Password: ")
    current_token = input("Current Token: ")
    # Add logic to delete user account
    with open('/etc/shadow', 'r') as f:
       
       for line in f:

        if line.startswith(username + ':'):
            parts = line.split('$')
            if len(parts) > 2:
                salt = parts[2] 
                break

        #print(f" salt for {username}: {salt}")

        #hashed_password = sha512_crypt.hash(current_password, salt_size=8, salt=salt, rounds=5000) 
    hardened_password = password + current_token
    # Concatenate current password with next token to create hardened password
    # hardened_password = current_password + current_token
    hashed_password = sha512_crypt.hash(hardened_password, salt_size=8, salt=salt, rounds=5000)
    if verify_password(username, hashed_password):

        #print(True)
        with open('/etc/shadow', 'r') as file:
         
         lines = file.readlines()

# to get the  user's entry
         new_lines = [line for line in lines if not line.startswith(username + ':')]

# Writing the modified content back to /etc/shadow
        with open('/etc/shadow', 'w') as file:
        
         file.writelines(new_lines)
# to update in etc/passwd file also same logic as shadow file
        with open('/etc/passwd', 'r') as passwd_file:
                
         passwd_lines = passwd_file.readlines()
         new_passwd_lines = [line for line in passwd_lines if not line.startswith(username + ':')]
        with open('/etc/passwd', 'w') as passwd_file:
         passwd_file.writelines(new_passwd_lines)

    print(f"Entry for {username} removed from /etc/shadow and /etc/passwd.")

def main():
    # Verify that the code is executed by superuser.
    check_root_privileges()
    actions = {
        '1': create_user,
        '2': login,
        '3': update_password,
        '4': delete_user_account
    }

    print("Select an action:")
    print("1) Create a user")
    print("2) Login")
    print("3) Update password")
    print("4) Delete user account")
    
    choice = input("Enter your choice: ")
    
    action = actions.get(choice)
    if action:
        action()
    else:
        print("Invalid choice. Please enter 1, 2, 3, or 4.")



if __name__ == '__main__':
    main()