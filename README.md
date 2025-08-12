# FormBuilder Django Project

## Overview

This is a Django-based FormBuilder application that enables users to create, edit, and manage custom forms with various field types. It includes secure user authentication, email verification, SMTP integration for email notifications, API key authentication for form submissions, and advanced features like reCAPTCHA and domain restriction for API calls.

---

## How the Project Works

- **User Authentication & Security**  
  The project uses a custom user model (`CustomUser`) with secure signup, login, logout, and email verification flows. Activation links are sent via email using token-based confirmation to ensure secure account activation.

- **Form & Field Management**  
  Users can create and edit forms with multiple fields like textarea, email, checkbox, date, etc. The forms and fields are stored in the database, and CRUD operations are supported via Django class-based views.

- **SMTP Integration & Email Notifications**  
  The project supports configuring SMTP credentials via forms. These credentials are verified by attempting an SMTP connection before use. Notifications are sent to users or admins using customizable email templates with dynamic content.

- **API Key Authentication & Domain Restriction**  
  Each form generates a unique API key. Form submissions through the API require the API key in the request header. Additionally, only requests from allowed domains configured by the user are accepted, ensuring secure form submission.

- **Security Features**  
  Includes CSRF protection, email verification, password reset functionality, and reCAPTCHA integration to protect against spam and unauthorized access.

- **Encryption & Security Libraries**  
  Uses `cryptography.fernet` for encryption tasks and secure handling of sensitive data.

- **Email Handling**  
  Utilizes Python’s built-in `smtplib` and `email` libraries for low-level SMTP communication and custom email message formatting.

---

## Installation & Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- PostgreSQL
- Access to an SMTP email service (Gmail SMTP)

### Steps

1. **Clone the repository**

   ```bash
   git clone https://github.com/nischal2005-gif/form-builder
   cd formbuilder

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate   


### Install Python Dependencies

- Django>=3.2
- cryptography
- requests
- six

3. **Install them by using**
   ```bash
   pip install -r requirements.txt

4. **Apply Migrations**
  ```bash
  python manage.py migrate

4. **Run the development server**
  ```bash
  python manage.py runserver