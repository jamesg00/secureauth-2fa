import tkinter as tk
from tkinter import messagebox
import bcrypt
import json
import requests
import os
import random
from cryptography.fernet import Fernet
from tkinter import font as tkFont
#James Garcia 6/23/2025

DATA_FILE = "users.json"        #This points to the users data file where all of the users data is stores (phone, psswd, user)
KEY_FILE = "secret.key"         #This is the key file used for encryption/decryption of phone numbers
FONT_PATH = "assets/RETROTECH.ttf"  #This points to a custom font file I added for my GUI


def load_or_create_key():
    if os.path.exists(KEY_FILE):        #This functions allows me to manage a encryption key used to encrypt/decrypt phone numbers
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:                                  #If there is no key file, it creates a new one, if there is one it loads the key
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        return key

fernet = Fernet(load_or_create_key()) #Fernet is a library I added to encrypt/decrypt phone numbers, its symmetric encryption capabilities allow me to encrypt the phone numbers before storing them in the JSON file


def load_users():
    if not os.path.exists(DATA_FILE):       #This function loads all of the users from the JSON file if it does not exist.
        return {}
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(DATA_FILE, 'w') as f:         #This function runs every time a user is created or updated, it saves the users data to the JSON file
        json.dump(users, f, indent=2)   #Json file is updated with the new user data, this is how the program keeps track of users


root = tk.Tk()
root.title("SecureAuth GUI 2FA")
root.geometry("350x350")            #This is initializing my GUI window using tkinter, a GUI library used in python
root.configure(bg="black")

# Load custom font (make sure RETROTECH.ttf is installed or replaced by a system font)
try:
    retrotech_font = tkFont.Font(family="RETROTECH", size=14)
except tk.TclError:

    retrotech_font = tkFont.Font(family="Courier New", size=14)


def clear_window():
    for widget in root.winfo_children():        #This function clears the window of all widgets, used to reset the GUI when switching between menus
        widget.destroy()

def mask_phone(phone):
    # Mask all but last 4 digits
    if len(phone) >= 4:
        return "***-***-" + phone[-4:]      #This function is specifically for the two way authentification, as you would send a code through the number, but the phone number will be masked on the GUI
    return phone        #Only returns the phone number if it is less than 4 digits, this is to prevent errors when masking the phone number


#Main menu leading to each function
def show_main_menu():
    clear_window()
    root.geometry("350x350")
    tk.Label(root, text="SecureAuth 2FA", font=retrotech_font, fg="lime", bg="black").pack(pady=30)
    tk.Button(root, text="Create Account", font=retrotech_font, width=20, command=create_account_gui).pack(pady=10)
    tk.Button(root, text="Login", font=retrotech_font, width=20, command=login_gui).pack(pady=10)
    tk.Button(root, text="Exit", font=retrotech_font, width=20, command=root.quit).pack(pady=10)


TEXTBELT_API_KEY = "212aab5bfa8f00361cb2694b8c280bf330ce36817SDkgmMYyuDkitMWBTnHvgoyr"
#This method is one of the methods I had found that is free to use for sending SMS messages, it uses the Textbelt API
#You have to sign up for a free key, which I have done, and it allows you to send a limited number of messages per day

def send_sms_textbelt(phone, message):
    response = requests.post('https://textbelt.com/text', {
        'phone': phone,
        'message': message,
        'key': TEXTBELT_API_KEY,  # free tier key for limited SMS I had purchased 3$ worth of 50 messages
    })
    result = response.json()
    if result.get('success'):
        print(f"[INFO] SMS sent to {phone}")        #This is a simple function that is the first step of the two way authentification system. if the message gets send and the user inputs the correct key, they are logged in
    else:
        print(f"[ERROR] SMS failed: {result.get('error')}")
    return result.get('success', False)


#This function clears the window and allows the user to create a new account, all of the data will then be saved to the JSON file

def create_account_gui():
    clear_window()
    root.geometry("350x400")
    
    tk.Label(root, text="Create Account", font=retrotech_font, fg="cyan", bg="black").pack(pady=15)

    tk.Label(root, text="Username:", font=retrotech_font, fg="white", bg="black").pack(anchor='w', padx=50)
    username = tk.Entry(root, font=retrotech_font)
    username.pack(padx=50, pady=5, fill='x')

    tk.Label(root, text="Password:", font=retrotech_font, fg="white", bg="black").pack(anchor='w', padx=50)
    password = tk.Entry(root, font=retrotech_font, show="*")
    password.pack(padx=50, pady=5, fill='x')

    tk.Label(root, text="Phone Number:", font=retrotech_font, fg="white", bg="black").pack(anchor='w', padx=50)
    phone = tk.Entry(root, font=retrotech_font)
    phone.pack(padx=50, pady=5, fill='x')

#After a account is created the user data will then be written to the JSON file but the data will be encrypted as to not be tampered with.
    def submit():
        u, p, ph = username.get().strip(), password.get().strip(), phone.get().strip()
        #u, p, ph are the username, password, and phone number respectively
        if not u or not p or not ph:
            messagebox.showerror("Error", "All fields are required!")
            return

        users = load_users()
        if u in users:
            messagebox.showerror("Error", "Username already exists!")
            return
        
        #the hashed_pw is the password that is hashed using bcrypt, this is to ensure that the password is not stored in plain text
        hashed_pw = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
        encrypted_phone = fernet.encrypt(ph.encode()).decode()

        #using fernet i was able to encrypt the phone number before storing it in the JSON file
        users[u] = {"password": hashed_pw, "phone": encrypted_phone}
        save_users(users)
        messagebox.showinfo("Success", "Account created successfully!")
        show_main_menu()

        #after it encrypts the phone number and saves the user data to the JSON file, it will then send a message to the phone number with a code

    tk.Button(root, text="Submit", font=retrotech_font, width=15, command=submit).pack(pady=15)
    tk.Button(root, text="Back", font=retrotech_font, width=15, command=show_main_menu).pack()

#This functions leads to the login GUI where the user can input their username and password
def login_gui():
    clear_window()
    root.geometry("350x300")
    
    tk.Label(root, text="Login", font=retrotech_font, fg="yellow", bg="black").pack(pady=15)

    tk.Label(root, text="Username:", font=retrotech_font, fg="white", bg="black").pack(anchor='w', padx=50)
    username = tk.Entry(root, font=retrotech_font)
    username.pack(padx=50, pady=5, fill='x')

    tk.Label(root, text="Password:", font=retrotech_font, fg="white", bg="black").pack(anchor='w', padx=50)
    password = tk.Entry(root, font=retrotech_font, show="*")
    password.pack(padx=50, pady=5, fill='x')

    login_button = tk.Button(root, text="Login", font=retrotech_font, width=15)
    login_button.pack(pady=15)
    
    tk.Button(root, text="Back", font=retrotech_font, width=15, command=show_main_menu).pack()

    def submit_login():

        #This is the second part of the two way authentification system, it checks if the user exists in the JSON file and if the password is correct
        # Disable login button right away
        login_button.config(state=tk.DISABLED)
        
        u, p = username.get().strip(), password.get().strip()

        if not u or not p:
            messagebox.showerror("Error", "Please enter both username and password.")
            login_button.config(state=tk.NORMAL)
            return

        users = load_users()
        if u not in users:
            messagebox.showerror("Error", "User not found.")
            login_button.config(state=tk.NORMAL)
            return
        


        stored_hash = users[u]["password"].encode()
        if not bcrypt.checkpw(p.encode(), stored_hash):
            messagebox.showerror("Error", "Wrong password.")
            login_button.config(state=tk.NORMAL)
            return

        encrypted_phone = users[u]["phone"].encode()
        phone = fernet.decrypt(encrypted_phone).decode()
        masked = mask_phone(phone)
        code = str(random.randint(100000, 999999))

    #first it wil try to use the textbelt API to send a SMS message to the phone number, if it fails it will show a warning and print the code to the console for testing purposes
        try:
            sent = send_sms_textbelt(phone, f"Your authentication code is: {code}")
        except Exception as e:
            sent = False
            print(f"[ERROR] Exception sending SMS: {e}")

        if not sent:
            messagebox.showwarning("Warning", "Failed to send SMS. The code will be shown here for testing.")
            print(f"[DEBUG] Your code is: {code}")

        clear_window()
        root.geometry("350x250")

        #This will show the code entry screen where the user can input the code sent to their phone

        tk.Label(root, text=f"Enter code sent to {masked}", font=retrotech_font, fg="orange", bg="black").pack(pady=20)
        code_entry = tk.Entry(root, font=retrotech_font)
        code_entry.pack(pady=10, padx=50, fill='x')

        #if the code matches the code sent to the phone number, the user will be logged in and the main menu will be shown
        #if the code does not match, an error message will be shown and the entry will
        def verify_code():
            entered = code_entry.get().strip()
            if entered == code:
                messagebox.showinfo("Success", "Authentication successful! Welcome.")
                show_main_menu()
            else:
                messagebox.showerror("Error", "Incorrect code, please try again.")
                code_entry.delete(0, tk.END)  # Clear entry on failure

        tk.Button(root, text="Verify", font=retrotech_font, width=15, command=verify_code).pack(pady=10)
        tk.Button(root, text="Back", font=retrotech_font, width=15, command=show_main_menu).pack()

    login_button.config(command=submit_login)

show_main_menu()
root.mainloop()
