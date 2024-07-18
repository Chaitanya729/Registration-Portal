import tkinter as tk
from tkinter import messagebox, Button, Frame
import re
import bcrypt
from cryptography.fernet import Fernet
import ast

# Decryption key. Must be securely stored in a file or database, but put here temporarily for the project
key = b'gkm3X24R6HeC3tA_zeDKHq5mVJVTP4iZFjHOSAvfITE='

with open("user_data.txt", "a") as file:
    pass

# Global dictionary and list to track login attempts
global_login_check_dict = {
    "email" : None,
    'username' : None,
    "attempts" : 3 
}

global_attempt_list = []

# Writing all the entries into a list, with the number of attempts
with open("user_data.txt", "r") as file:
    for line in file:
        profession, user_name, password, name, email, department, *other_details  = line.strip().split(",")
        if profession == 'Teacher' or profession == 'Student':
            global_attempt_list.append({"email" : email, "username" : user_name,"attempts" : 3})
        else:
            global_attempt_list.append({"email" : email,"username" : user_name,"attempts" : 0})

# Person Class
class Person:
    def __init__(self, profession, user_name, password, name, email):  # Basic Attributes
        self.profession = profession
        self.user_name = user_name
        self.password = password
        self.name= name
        self.email = email

# Teacher Class
class Teacher(Person):
    def __init__(self, profession, user_name, password, name, email, department):   # Initializing the teacher class
        super().__init__(profession, user_name, password, name, email)
        self.profession = 'Teacher'
        self.department = department

# Student Class
class Student(Person):
    def __init__ (self, profession, user_name, password, name, email, department, program, graduating_year):  # Initializing the student class
        super().__init__(profession, user_name, password, name, email)
        self.profession = 'Student'
        self.department = department
        self.graduating_year = graduating_year
        self.program = program

# UGStudent Class
class UGStudent(Student):
    def __init__ (self, profession, user_name, password, name, email, department, program, graduating_year: int):   # Initializing the UGStudent class
        super().__init__(profession, user_name, password, name, email, department, program, graduating_year)
        self.program = "UG"

# PGStudent Class
class PGStudent(Student):
    def __init__(self,profession, user_name, password, name, email, department, program, graduating_year: int):  # Initializing the PGStudent class
        super().__init__(profession, user_name, password, name, email, department, program, graduating_year)
        self.program = "PG"

# Function to encrypt the password
def encrypt_password(password):
    global key
    fernet = Fernet(key)
    return fernet.encrypt(password.encode())

 # Function to decrypt the password

# Function to decrypt the password
def decrypt_password(encrypted_password):
    global key
    bytestring_decrypt_password = ast.literal_eval(encrypted_password)
    fernet = Fernet(key)
    return fernet.decrypt(bytestring_decrypt_password).decode()

# Function to append the newly created user to the global attempts list
def write_to_global_list(email, user_name):
    global global_attempt_list
    global_attempt_list.append({"email" : email, "username" : user_name,"attempts" : 3})

# Function to validate the password
def valid_password_input(password):
    if len(password) < 8 or len(password) > 12:         # Checks length of password
        return False
    if not any(char.isdigit() for char in password):    # Checks if password has a digit
        return False
    if not any(char.isupper() for char in password):    # Checks if password has an uppercase letter
        return False
    if not any(char.islower() for char in password):    # Checks if password has a lowercase letter
        return False
    if not any(char in "!@#$%&*" for char in password): # Checks if password has a special character
        return False
    if any(char in " " for char in password):           # Checks if password has a space
        return False
    return True

# Function to check if the given identifier (i.e email or username) is unique
def unique_identifier(identifier):
    with open("user_data.txt", "r") as file:        # Opening the file
        for line in file:
            profession, user_name, password, name, email, department, *other_details  = line.strip().split(",")     # Splitting the line into a list, and extracting required details
            if user_name == identifier or email == identifier:
                return False
    return True 

# Modify the details of the user in the file
def modify_in_file(old_username, new_details):
    with open("user_data.txt", "r") as file:
        lines = file.readlines()
    with open("user_data.txt", "w") as file:
        for line in lines:
            profession, username, *other_details = line.strip().split(",")
            if username == old_username:
                new_details[2] = str(encrypt_password(new_details[2]))
                file.write(f"{','.join(new_details)}\n")
            else:
                file.write(line)

# Delete the user ( from the file)         
def delete_from_file(user_name):
    with open("user_data.txt", "r") as file:
        lines = file.readlines()
    with open("user_data.txt", "w") as file:
        for line in lines:
            profession, username, *other_details = line.strip().split(",")
            if(username != user_name):
                file.write(line)

# Function to find the position of the record in the file
def find_record_position(filename, identifier):
    with open(filename, 'r') as file:
        for line_number, line in enumerate(file, start=1):
            original_details = []
            original_details = line.strip().split(",")
            if identifier == original_details[1] or identifier == original_details[4]:
                return original_details
    return None

# Checking if the user_name and password match, along with determining activity status 
def validate_login(identifier, password):

    with open("user_data.txt", "r") as file:
        for line in file:
            profession, user_name, actual_password, name, email, *other_details = line.strip().split(",")
            if user_name == identifier or email == identifier:
                if decrypt_password(actual_password) == password:
                    if profession == "Teacher" or profession == "Student":      # Account is active
                        return "Details Matched"
                    else:                                                       # Account is inactive
                        return "Inactive Account"
                else:                                                           # Password Incorrect
                    return "Password Incorrect"                     
    
    return "User Not Found"                                                     # User Not Found by default

# Function to enter the details of the student into the file
def register_student(user_name, password, name, email, department, program, graduating_year):
    student = Student(user_name, password, name, email, department, program, graduating_year)
    with open("user_data.txt", "a") as file:
        # Writing into the file
        file.write(f"{student.profession},{student.user_name},{student.password},{student.name},{student.email},{student.department},{student.program},{student.graduating_year}\n")

# Function to enter the details of the teacher into the file
def register_teacher(user_name, password, name, email, department):
    teacher = Teacher(user_name, password, name, email, department)
    with open("user_data.txt", "a") as file:
        # Writing into the file
        file.write(f"{teacher.profession},{teacher.user_name},{teacher.password},{teacher.name},{teacher.email},{teacher.department},{teacher.authenticated}, {teacher.active}\n")

# Function to modify the email in the global list
# Used in case a user updates their email midway through the program
def modify_email_in_global_list(old_email, new_email):
    for x in global_attempt_list:
        if x["email"] == old_email:
            x["email"] = new_email          # Updating to the new email
            return

# Registration page GUI
def registration_gui():

    # Initializing the root
    root = tk.Tk()
    root.geometry("700x700")
    root.title("Registration Page")
    bg = "#02CCFE"  # Light Blue
    root.configure(bg=bg)

    # Variables to hold dynamically created widgets
    dynamic_widgets = []

    global department_entry, program_entry, graduating_year_entry

    # Function to clear dynamic widgets
    def clear_dynamic_widgets():
        for widget in dynamic_widgets:
            widget.destroy()
        dynamic_widgets.clear()

    # Function handling teacher records
    def submit_teacher():
        
        name = name_entry.get()
        user_name = username_entry.get()
        password = password_entry.get()
        email = email_entry.get()
        department = department_entry.get()
        teacher = Teacher('Teacher', user_name, password, name, email, department)

        # Validate email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Error", "Email entered is wrong. Please enter the details again.")
            email_entry.delete(0, tk.END)  # Clear the entry field
            return  # Don't continue with registration
        
        if not valid_password_input(password):
            messagebox.showerror(title="Invalid Password", message="The password you entered is invalid. Please try again.")
            password_entry.delete(0, tk.END)  # Clear the entry field
            return  # Don't continue with registration
        
        if not unique_identifier(user_name) or user_name == '':
            messagebox.showerror(title="Username Already Exists", message="The username you entered already exists. Please try again.")
            username_entry.delete(0, tk.END)
            return
        
        if not unique_identifier(email) or user_name == '':
            messagebox.showerror(title="Email Already Exists", message="The email you entered already exists. Please try again.")
            email_entry.delete(0, tk.END)
            return
        
        # Appending the email to the global list, with 3 attempts
        write_to_global_list(email, user_name)

        # Writing to the file
        with open("user_data.txt", "a") as file:
            file.write(f"{teacher.profession},{teacher.user_name},{encrypt_password(teacher.password)},{teacher.name},{teacher.email},{teacher.department}\n")

        root.destroy()
        messagebox.showinfo(title="Registration Successful", message="You have successfully registered.")
        main_page()

    # Function handling student records
    def submit_student():
        name = name_entry.get()
        user_name = username_entry.get()
        password = password_entry.get()
        email = email_entry.get()
        department = department_entry.get()
        program = program_entry.get()
        graduating_year = graduating_year_entry.get()
        student = Student('Student', user_name, password, name, email, department, program, graduating_year)

        # Validate email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Error", "Email entered is wrong. Please enter the details again.")
            email_entry.delete(0, tk.END)
            return # Don't continue with registration
        
        # Validate Password
        if not valid_password_input(password):
            messagebox.showerror(title="Invalid Password", message="The password you entered is invalid. Please try again.")
            password_entry.delete(0, tk.END)  # Clear the entry field
            return  # Don't continue with registration

        if not unique_identifier(user_name) or user_name == '':
            messagebox.showerror(title="Username Already Exists", message="The username you entered already exists. Please try again.")
            username_entry.delete(0, tk.END)
            return
        
        if not unique_identifier(email) or email == '':
            messagebox.showerror(title="Email Already Exists", message="The email you entered already exists. Please try again.")
            email_entry.delete(0, tk.END)
            return
        
        if(program != "UG" and program != "PG"):
            messagebox.showerror(title="Invalid Program", message="The program you entered is invalid. Please try again.")
            program_entry.delete(0, tk.END)
            return
        
        # Appending to the Global List
        write_to_global_list(email, user_name)

        # Writing to the file
        with open("user_data.txt", "a") as file:
            file.write(f"{student.profession},{student.user_name},{encrypt_password(student.password)},{student.name},{student.email},{student.department},{student.program},{student.graduating_year}\n")
        
        root.destroy()
        messagebox.showinfo(title="Registration Successful", message="You have successfully registered.")
        main_page()


    # Name entry
    name_label = tk.Label(root, text="Name", font=("Helvetica", 16, "bold"))
    name_label.pack(side=tk.TOP, pady = (20,3))
    name_entry = tk.Entry(root, font=("Helvetica", 16))
    name_entry.pack()

    # Username Label
    username_label = tk.Label(root, text="Username", font=("Helvetica", 16, "bold"))
    username_label.pack(pady = (10,3))
    username_entry = tk.Entry(root, font=("Helvetica", 16))
    username_entry.pack()

    # Email Label
    email_label = tk.Label(root, text="Email", font=("Helvetica", 16, "bold"))
    email_label.pack(pady = (10,3))
    email_entry = tk.Entry(root, font=("Helvetica", 16))
    email_entry.pack()

    # Password Label
    password_label = tk.Label(root, text="Password", font=("Helvetica", 16, "bold"))
    password_label.pack(pady = (10,3))
    password_entry = tk.Entry(root, show="\u25cf")
    password_entry.pack()

    def toggle_password_visibility():
        if password_entry.cget("show") == "\u25cf":
            password_entry.config(show="")
        else:
            password_entry.config(show="\u25cf")

    show_password_button = tk.Button(root, text="Show Password", command=toggle_password_visibility)
    show_password_button.pack(pady= (0,10))
    # Exiting to the main page
    def go_back():
        root.destroy()
        main_page()
    
    # Button to go back to the main page
    main_page_button = tk.Button(root, text="Back", font=("Helvetica", 16, "bold"), command=go_back)
    main_page_button.pack(side=tk.BOTTOM, pady = 20)

    # Function to dynamically add fields based on occupation
    def add_fields(occupation):
        clear_dynamic_widgets()

        global department_entry, program_entry, graduating_year_entry
        if occupation == "Teacher":
            department_label = tk.Label(root, text="Department", font=("Helvetica", 16, "bold"))
            department_label.pack(pady = (10,3))
            department_entry = tk.Entry(root, font=("Helvetica", 16))
            department_entry.pack()

            submit_button = tk.Button(root, text="Submit", font=("Helvetica", 16, "bold"), command=submit_teacher)
            submit_button.pack(side=tk.BOTTOM, pady=(5, 40))

            dynamic_widgets.extend([department_label, department_entry, submit_button])

        elif occupation == "Student":
            department_label = tk.Label(root, text="Department", font=("Helvetica", 16, "bold"))
            department_label.pack(pady = (10,3))
            department_entry = tk.Entry(root, font=("Helvetica", 16))
            department_entry.pack()

            program_label = tk.Label(root, text="Program (UG / PG)", font=("Helvetica", 16, "bold"))
            program_label.pack(pady = (10,3))
            program_entry = tk.Entry(root, font=("Helvetica", 16))
            program_entry.pack()

            graduating_year_label = tk.Label(root, text="Graduating Year", font=("Helvetica", 16, "bold"))
            graduating_year_label.pack()
            graduating_year_entry = tk.Entry(root, font=("Helvetica", 16))
            graduating_year_entry.pack()

            submit_button = tk.Button(root, text="Submit", font=("Helvetica", 16, "bold"), command=submit_student)
            submit_button.pack(side=tk.BOTTOM, pady=(5, 40))

            dynamic_widgets.extend([department_label, department_entry, program_label, program_entry, graduating_year_label, graduating_year_entry, submit_button])

    # Occupation OptionMenu
    occupation_options = ["Teacher", "Student"]
    occupation = tk.StringVar(root)
    occupation.set(occupation_options[0])  # default value
    occupation_menu = tk.OptionMenu(root, occupation, *occupation_options, command=add_fields)
    occupation_menu.pack(pady=(5,5))

    # Call add_fields initially to set up default fields
    add_fields(occupation.get())

    root.mainloop()

# Function to deactivate the user
def deactivate_user(identifier):
    with open("user_data.txt", "r") as file:
        lines = file.readlines()
    with open("user_data.txt", "w") as file:
        for line in lines:
            profession, username, password, email, *other_details = line.strip().split(",")
            if username == identifier or email == identifier:

                # Changing the activity status

                if profession == "Teacher":
                    profession = "Inactive Teacher"
                elif profession == "Student":
                    profession = "Inactive Student"
                line = ",".join([profession, username, password, email] + other_details) + "\n"
            file.write(line)

# The login page
def login_gui():

    # Function to deal with the login details submission
    def login_handle():
        identifier = identifier_entry.get()
        password = password_entry.get()
        match = validate_login(identifier, password)
        
        if match == "Details Matched":      # If the details match
            root.destroy()
            display_page(find_record_position("user_data.txt", identifier))
            for x in global_attempt_list:
                if(x["email"] == identifier or x["username"] == identifier):
                    x["attempts"] = 3
            messagebox.showinfo(title="Login Successful", message="You have successfully logged in.")
            

        elif match == 'Inactive Account':   # If the account is inactive
            identifier_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
            messagebox.showerror(title="Inactive Account", message="Your account has been deactivated. Please contact the administrator for further details.")
            return  
        
        elif match == 'Password Incorrect': # If the password is incorrect
            password_entry.delete(0, tk.END)

            # Checking for the number of attempts left
            for x in global_attempt_list:
                if (x["email"] == identifier or x["username"] == identifier) and x["attempts"] > 0:     # There are some more attempts left
                    x["attempts"] -= 1
                    if x["attempts"] == 0:
                        identifier_entry.delete(0, tk.END)
                        messagebox.showerror(title="Account Locked", message="Your account has been locked. Please contact the administrator for further details.")
                        deactivate_user(identifier)
                        return
                    else:
                        messagebox.showerror(title="Password Incorrect", message="The password you entered is incorrect. Please try again.\nYou have " + str(x["attempts"]) + " attempts left.")
                        return
                else:                                                                                # No more attempts left    
                    identifier_entry.delete(0, tk.END)
                    messagebox.showerror(title="Account Locked", message="Your account has been locked. Please contact the administrator for further details.")
                    return
            return
        elif match == 'User Not Found':     # If the user is not found
            identifier_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
            messagebox.showerror(title="User Not Found", message="The user you entered is not found. Please try again.")
            return
    
    # Function to go back to the main page
    def go_back():
        root.destroy()
        main_page()

    # Intializing the root
    root = tk.Tk()
    root.geometry("500x500")
    root.title("Login Page")
    bg = "#02CCFE"  # Light Blue
    fg = '#ffffff'  # White
    root.configure(bg=bg)

    # Indentifier Label
    identifier_label = tk.Label(root, text="User ID or Email", font=("Helvetica", 16, "bold"))
    identifier_label.pack(pady = (20,5))
    identifier_entry = tk.Entry(root, font=("Helvetica", 16))
    identifier_entry.pack()

    # Password Label
    password_label = tk.Label(root, text="Password", font=("Helvetica", 16, "bold"))
    password_label.pack(pady = (20,5))

    # Password entry and show password button
    password_entry = tk.Entry(root, show="\u25cf")
    password_entry.pack()
    
    def toggle_password_visibility():
        if password_entry.cget("show") == "\u25cf":
            password_entry.config(show="")
        else:
            password_entry.config(show="\u25cf")

    show_password_button = tk.Button(root, text="Show Password", command=toggle_password_visibility)
    show_password_button.pack(pady= (0,0))

    # Addding a frame to create a gap between the buttons
    frame = Frame(root, height=50, bg=bg)
    frame.pack()

    # Login Button
    login_button = tk.Button(root, text="Login", font=("Helvetica", 16, "bold"), command=login_handle)
    login_button.pack()

    # Addding a frame to create a gap between the buttons
    frame = Frame(root, height=50, bg=bg)
    frame.pack()

    # Back Button
    back_button = tk.Button(root, text="Back", font=("Helvetica", 16, "bold"), command=go_back)
    back_button.pack()

    root.mainloop()

# The update profile page
def update_profile_gui(details_list):

    # Initializing the root
    root = tk.Tk()
    root.geometry("600x700")
    root.title("Update Profile")
    bg = "#02CCFE"  # Light Blue
    fg = '#ffffff'  # White
    root.configure(bg=bg)        

    # Function that updates the details into the file
    def update_profile_handle():
        new_name = new_name_entry.get()
        new_username = new_username_entry.get()
        new_email = new_email_entry.get()
        current_password = current_password_entry.get()
        new_password = new_password_entry.get()
        confirm_new_password = confirm_new_password_entry.get()

        # If all the fields are empty
        if new_name == "" and new_username == "" and new_email == "" and current_password == "" and new_password == "" and confirm_new_password == "":
            messagebox.showerror(title="No Details !!!", message="Please enter the details you want to update.")
            return

        # If the user wants to update the name
        if not unique_identifier(new_username) and new_username != '':
            messagebox.showerror(title="Name Already Exists", message="The name you entered already exists. Please try again.")
            new_name_entry.delete(0, tk.END)
            return
        
        # If the user wants to update the username
        if not unique_identifier(new_email) and new_email != '':
            messagebox.showerror(title="Email Already Exists", message="The email you entered already exists. Please try again.")
            new_email_entry.delete(0, tk.END)
            return
        
        # Checking if the password is correct
        if current_password != decrypt_password(details_list[2]):
            messagebox.showerror(title="Password Incorrect", message="The password you entered is incorrect. Please try again.")
            current_password_entry.delete(0, tk.END)
            new_password_entry.delete(0, tk.END)
            confirm_new_password_entry.delete(0, tk.END)
            return
        else:
            # Checking if the new password and confirm new password match
            if new_password != confirm_new_password:
                messagebox.showerror(title="Password Mismatch", message="The passwords you entered do not match. Please try again.")
                new_password_entry.delete(0, tk.END)
                confirm_new_password_entry.delete(0, tk.END)
                return
            # Checking if the new password is valid
            elif not valid_password_input(new_password) and new_password != '': 
                messagebox.showerror(title="Invalid Password", message="The password you entered is invalid. Please try again.")
                new_password_entry.delete(0, tk.END)
                confirm_new_password_entry.delete(0, tk.END)
                return
        
        # Variables to keep track of old details to be used in the modify_in_file function
        old_username = details_list[1]
        old_email = details_list[4]

        # Temporarily updating the list so that the display page doesn't get affected
        if(new_username != ''): details_list[1] = new_username
        if(new_password != ''): details_list[2] = new_password
        if(new_name != ''): details_list[3] = new_name
        if(new_email != ''): 
            details_list[4] = new_email
            modify_email_in_global_list(old_email, new_email)

        # Modifying the details into the file
        modify_in_file(old_username, details_list)

        # Update successfull
        root.destroy()
        messagebox.showinfo(title="Update Successful", message="You have successfully updated your profile.")
        display_page(details_list)

    # Function to go back to the display page
    def go_back():
        root.destroy()
        display_page(details_list)

    # Name Label
    new_name_label = tk.Label(root, text="New Name", font=("Helvetica", 16, "bold"))
    new_name_label.pack(pady = (30,5))
    new_name_entry = tk.Entry(root, font=("Helvetica", 16))
    new_name_entry.pack()

    # Username Label
    new_username_label = tk.Label(root, text="New Username", font=("Helvetica", 16, "bold"))
    new_username_label.pack(pady = (5,5))
    new_username_entry = tk.Entry(root, font=("Helvetica", 16))
    new_username_entry.pack()

    # Email Label
    new_email_label = tk.Label(root, text="New Email", font=("Helvetica", 16, "bold"))
    new_email_label.pack(pady = (5,5))
    new_email_entry = tk.Entry(root, font=("Helvetica", 16))
    new_email_entry.pack()

    # Password Label
    current_password_label = tk.Label(root, text="Current Password", font=("Helvetica", 16, "bold"))
    current_password_label.pack(pady = (5,5))
    current_password_entry = tk.Entry(root, show="\u25cf")
    current_password_entry.pack()

    def toggle_password_visibility():
        if current_password_entry.cget("show") == "\u25cf":
            current_password_entry.config(show="")
        else:
            current_password_entry.config(show="\u25cf")

    show_password_button = tk.Button(root, text="Show Password", command=toggle_password_visibility)
    show_password_button.pack(pady= (0,0))

    # New Password Label
    new_password_label = tk.Label(root, text="New Password", font=("Helvetica", 16, "bold"))
    new_password_label.pack(pady = (10,5))
    new_password_entry = tk.Entry(root, show="\u25cf")
    new_password_entry.pack()

    def toggle_new_password_visibility():
        if new_password_entry.cget("show") == "\u25cf":
            new_password_entry.config(show="")
        else:
            new_password_entry.config(show="\u25cf")

    show_password_button = tk.Button(root, text="Show Password", command=toggle_new_password_visibility)
    show_password_button.pack(pady= (0,0))

    # Confirm New Password Label
    confirm_new_password_label = tk.Label(root, text="Confirm New Password", font=("Helvetica", 16, "bold"))
    confirm_new_password_label.pack(pady = (10,5))
    confirm_new_password_entry = tk.Entry(root, show="\u25cf")
    confirm_new_password_entry.pack()

    def toggle_confirm_new_password_visibility():
        if confirm_new_password_entry.cget("show") == "\u25cf":
            confirm_new_password_entry.config(show="")
        else:
            confirm_new_password_entry.config(show="\u25cf")

    show_password_button = tk.Button(root, text="Show Password", command=toggle_confirm_new_password_visibility)
    show_password_button.pack(pady= (0,0))
    # Frame to create a gap between the buttons
    frame = Frame(root, height=30, bg=bg)
    frame.pack()

    # Submit Button
    submit_button = tk.Button(root, text="Submit", font= ('−*−lucidatypewriter−medium−r−*−*−*−140−*−*−*−*−*−*', 16, "bold"), command= update_profile_handle)
    submit_button.pack(side=tk.BOTTOM, pady = (20,20))

    # Back Button
    back_button = tk.Button(root, text="Back", font=("−*−lucidatypewriter−medium−r−*−*−*−140−*−*−*−*−*−*", 16, "bold"), command=go_back)
    back_button.pack(side=tk.BOTTOM, pady = (20,20))

# The display page
def display_page(details_list):

    # Intializing the root
    root = tk.Tk()
    root.geometry("500x500")
    root.title("Personal Page")
    bg = "#02CCFE"  # Light Blue
    fg = '#ffffff'  # White
    root.configure(bg=bg)
    
    # Function to go to the update profile page
    def update_profile():
        root.destroy()
        update_profile_gui(details_list)

    # Function to delete the profile
    def delete_profile():
        confirm = messagebox.askyesno(title="Confirmation", message="Are you sure you want to deregister?")
        if confirm:     
            # Deleting from the file
            root.destroy()
            delete_from_file(details_list[1])
            messagebox.showinfo(title="Deregistration Successful", message="You have successfully deregistered.\nPlease contact the administrator for further details.")
            main_page()

    # Welcome Label
    welcome_label = tk.Label(root, text="Welcome " + details_list[3] + "!!!", font=("Helvetica", 20, "bold"))
    welcome_label.pack(pady = (20,5))

    # Frame to create a gap between the buttons
    frame = Frame(root, height=50, bg=bg)
    frame.pack()

    # Update Profile Button
    update_profile_button = tk.Button(root, text="Update Profile", font=("Helvetica", 16, "bold"), command=update_profile)
    update_profile_button.pack(pady = (20,30))

    frame = Frame(root, height=50, bg=bg)
    frame.pack()

    # Deregister Button
    deregister_button = tk.Button(root, text="Deregister", font=("Helvetica", 16, "bold"), fg="#FF1818", command=delete_profile)
    deregister_button.pack(pady = (20,5))

    # Logout function
    def logout():
        root.destroy()
        main_page()
    
    # Logout Button
    logout_button = tk.Button(root, text="Logout", font=("Helvetica", 16, "bold"), command=logout)
    logout_button.pack(side=tk.BOTTOM, pady = 20)

# Main page
def main_page():

    # Function to go to the login page
    def login():
        root.destroy()
        login_gui()
    
    # Function to go to the registration page
    def register():
        root.destroy()
        registration_gui()
    
    # Function to terminate the session
    def terminate():
        messagebox.showinfo(title="Session Terminated", message="Thank you for visiting Mini-Moodle !!!")
        root.destroy()

    # Initializing the root
    root = tk.Tk()
    root.geometry("500x500")
    root.title("Mini-Moodle")

    bg = "#02CCFE"  # Light Blue
    fg = '#ffffff'  # White
    root.configure(bg=bg)

    welcome_label = tk.Label(root, text="Welcome to Mini-Moodle !!!", font=("Helvetica", 26, "bold"))
    welcome_label.pack(side=tk.TOP, pady = (20,0))

    # Addding a frame to create a gap between the buttons
    frame = Frame(root, height=50, bg=bg)
    frame.pack()

    # Login Button
    login_button = tk.Button(root, text="Login", font=("Helvetica", 16, "bold"), command=login)
    login_button.pack()

    frame = Frame(root, height=50, bg=bg)
    frame.pack()

    # Register Label
    register_label = tk.Label(root, text="New User?? Register here!!!", font=("Helvetica", 18, "bold"))
    register_label.pack()
    # Register Button
    register_button = tk.Button(root, text="Register", font=("Helvetica", 16, "bold"), command=register)
    register_button.pack(pady=(50,0))

    # Terminate Button
    terminate_button = tk.Button(root, text="Terminate Session", font=("Helvetica", 16, "bold"), command=terminate)
    terminate_button.pack(side=tk.BOTTOM, pady = 20)

    root.mainloop()


main_page()

