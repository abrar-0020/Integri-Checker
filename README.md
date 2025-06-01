# Blockchain-Based File Integrity Checker

A desktop application built with Python and Tkinter that uses blockchain principles to verify the integrity of files on your computer.

---

## 🔐 Features

- ✅ Add individual files or entire folders to the blockchain for integrity tracking.
- 🔍 Check if files have been **tampered with**, **modified**, or **deleted** by comparing current file hashes with stored ones.
- 🗑️ Remove single files or clear the entire blockchain.
- 🖥️ GUI displays: file name, hash, and status (UNCHANGED, TAMPERED, MISSING).
- 🔗 Uses a simple blockchain structure to securely store file hash records.

---

## ⚙️ How It Works

Each file added is hashed using **SHA256** and saved as a block in a blockchain-like structure.  
When checking integrity, the app recomputes the file hash and compares it to the stored one:

- 🟢 UNCHANGED – hash matches
- 🔴 TAMPERED – file changed
- ⚠️ MISSING – file no longer exists

This ensures both the integrity of the file **and** the integrity of the recorded data.

---

## 📦 Installation & Usage

### Step 1: Download the Project Files

**Option 1:**  
Download as ZIP from GitHub:
- Click the **Code** button
- Select **Download ZIP**
- Extract to any folder

**Option 2:**  
Clone with Git:
```bash
git clone https://github.com/abrar-0020/Integri-Checker.git

Step 2: Prepare the Environment

Ensure Python 3.x is installed: https://python.org
This app uses only built-in libraries:
tkinter
hashlib
pickle
✅ No need to install external packages.

Step 3: Run the Application

In terminal or command prompt, run:
python IntegriCheck.py
Or just double-click IntegriCheck.exe (if available) to run the app without Python.

🧪 Technologies Used

Python 3.x
Tkinter – for GUI
hashlib – for SHA256 hashing
pickle – for storing blockchain data

🗂️ Project Structure

Integri-Checker/
├── IntegriCheck.py         # Main application script
├── IntegriCheck.exe        # Compiled executable (optional)
├── app_icon.ico            # App icon
├── blockchain_data.pkl     # Stored blockchain data
└── README.md               # This file

⚠️ Windows Defender Warning
When you run IntegriCheck.exe for the first time, Windows Defender SmartScreen may show a warning like:

"Windows protected your PC"

This is expected because the app is not signed with a verified certificate.
To proceed:
-Click More info
-Click Run anyway

✅ The application is safe to use.

📄 License
This project is open-source and free to use under the MIT License.

