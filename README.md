# Secure File Sharing web app
## Overview

This project is a secure file sharing platform built with Flask, SQLAlchemy, and HashiCorp Vault. The platform allows users to upload files, encrypt them, and share them securely within specified groups. HashiCorp Vault is utilized as the key manager for securely storing and managing encryption keys.

## Features

- User authentication and authorization
- File encryption and decryption using AES encryption algorithm
- Role-based access control for file sharing within groups
- Password hashing for user authentication security
- Email notifications for password resets and file sharing
- Secure key management with HashiCorp Vault

## Setup

1. Clone the repository:

    ```bash
    git clone https://github.com/OAAmine/Share-Files-Safely
    cd Share-Files-Safely
    ```

2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Set up HashiCorp Vault:
   
   - Follow the official [HashiCorp Vault documentation](https://learn.hashicorp.com/tutorials/vault/getting-started-install) to install and configure HashiCorp Vault.
   - Configure HashiCorp Vault to use as the key manager for encryption keys in ``main.py``.

4. Configure the Flask application:
   
   - Open `main.py` and update the configurations related to HashiCorp Vault, SMTP server, database URI, and other settings according to your environment.

5. Initialize the database:
   
   - Run the following commands to create the database and tables:
   
     ```bash
        mysql -u <username> -p <password> < database_schema.sql
     ```

6. Run the application:
   
   - Start the Flask application:
   
     ```bash
     python main.py
     ```

7. Access the application:
   
   - Open a web browser and navigate to `https://localhost:81` (or the specified host and port).

## Usage

- Users can sign up for an account, log in, and upload files securely.
- Files are encrypted using AES encryption algorithm and stored securely.
- Users can share files securely within specified groups.
- Email notifications are sent for password resets and file sharing activities.

## License

This project is licensed under the [MIT License](LICENSE).
