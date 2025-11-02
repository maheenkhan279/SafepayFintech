🏦 SafePay FinTech – Secure Financial Web App
🔹 Overview

SafePay FinTech is a Streamlit-based web application designed to provide secure financial data management using encryption, decryption, and authentication features.
It allows users to register, log in, encrypt/decrypt passwords, upload files, and input transaction data safely.
The app follows strong cybersecurity principles such as input validation, password strength checks, session handling, and activity tracking.

⚙️ Key Features

User Registration & Login – Create a secure account and log in safely.

Password Encryption – Uses strong encryption to store passwords securely.

Password Decryption – Only authorized users can decrypt their data.

File Upload Security – Uploads are checked to prevent malicious files (e.g., .exe).

Input Validation – Prevents SQL injection, script attacks, and invalid data entries.

Session & Logout Handling – Logs out automatically after inactivity or on request.

Activity Tracking – Logs every user’s registration, login, encryption, and upload actions.

Numeric Input Fields – Secure amount entry for financial operations.

Email Validation & Password Strength Check – Prevents weak or invalid inputs.

Error Handling – Prevents the display of system errors or code traces.

🧠 Technologies Used

Python 3

Streamlit

Fernet Encryption (from cryptography library)

JSON (for user and activity storage)

Regular Expressions (for input & email validation)

🚀 How to Run the App

Open your project folder in VS Code or any IDE.

Run the following command in the terminal:

streamlit run App.py


The app will open automatically in your browser.

Use the sidebar to Register, Login, Encrypt, Decrypt, or Upload Files.

🧩 Test Cases Performed
No	Test Name	Description	Expected Outcome
1	SQL Injection	Tried ' OR 1=1--	Input rejected
2	Weak Password	Entered 12345	Warning shown
3	Special Character Input	Entered <script>	Escaped output
4	Unauthorized Access	Tried opening dashboard without login	Redirected to login
5	Session Expiry	Stayed idle 5 mins	Auto logout
6	Logout Functionality	Clicked logout	Session cleared
7	Data Confidentiality	Checked DB	Encrypted passwords
8	File Upload Validation	Uploaded .exe	File rejected
9	Error Leakage	Entered invalid query	Generic error only
10	Input Length Validation	Typed 5000 chars	Validation triggered
11	Duplicate Registration	Same username	Error displayed
12	Number Field Validation	Letters in number field	Rejected
13	Password Match	Mismatched passwords	Registration blocked
14	Data Modification	Changed transaction ID manually	Access denied
15	Email Validation	Entered abc@	Error shown
16	Account Lockout	5 failed logins	Account locked
17	Secure Error Handling	Divide by zero test	Controlled error
18	Encrypted Record Check	Viewed DB	Data unreadable
19	Unicode Input	Emoji input	Handled gracefully
20	Empty Field	Left blank	Warning shown
👩‍💻 Developer

Developed by: Maheen Khan
App Name: SafePay FinTech
Purpose: To demonstrate secure fintech app design with encryption, validation, and data protection.