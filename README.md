# SecureAuth 2FA

Two Way Authentification App is a simple and secure Python app that lets users create an account and log in using two-factor authentication (2FA). After entering the correct username and password, the user receives a one-time verification code via SMS to complete the login process.

---

How to Use
1. Create Account:
  -Click "Create Account"
  -Enter a username, password, and your phone number
  -Submit to save your account (data is stored locally)
2. Log In:
  -Click "Login"
  -Enter your username and password
  -If credentials are correct, a 6-digit code will be sent to your phone
  -Enter the code to finish logging in
3. SMS Not Working?:
  -If SMS sending fails (e.g., you hit your daily Textbelt limit), the code will be printed in the terminal so you can still test the login

Features:
- Account creation with:
  - Username
  - Password (hashed with bcrypt)
  - Phone number (encrypted for security)
- Login system that checks your password and sends a 6-digit code to your phone
- Text messages sent using the Textbelt API
- If Textbelt fails, the code is printed in the console so you can still test it

How It Works:
When a user signs up, the app saves their info in a JSON file:
- Passwords are hashed (so they’re never stored in plain text)
- Phone numbers are encrypted using a key saved locally

When logging in:
- The password is checked against the hash
- If it’s correct, a 6-digit code is sent to the saved phone number via Textbelt
- The user then enters the code to complete the login

Requirements:
You’ll need Python 3.10 or newer, plus these libraries:
pip install bcrypt cryptography requests

This python file uses a method of Textbelt for sending the authentification method, however if there is no textbelt key available the code will display a "dummy" key on the terminal to simulate a SMS code sent to a telephone
![image](https://github.com/user-attachments/assets/ff3a3a99-05fa-4a98-807b-942c6dbf4370)
![image](https://github.com/user-attachments/assets/af1718ab-fe1d-4c4b-a851-7e4148a139b6)
