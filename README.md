# Simple Secure Application for Making Posts

## Starting the Application
*This project requires Docker to run. Make sure you have Docker and Docker Compose installed.* \
To start the application, use the following command:

```bash
  docker-compose up
```

You can access the application through:

- [https://localhost](https://localhost)  
  (with automatic redirect from `http://localhost`)

If you'd like to access the backend server directly (bypassing the proxy), you can do so via:

- [https://localhost:8081](https://localhost:8081) (Backend with HTTPS) \
  (with automatic redirect from `http://localhost:8080`)

### SQLite Error Troubleshooting:
If you encounter an SQLite error, please check your database.db file permissions and ensure that they are set to writable.

## Core Features

- **Two-Factor Authentication (2FA)** using TOTP (Time-based One-Time Password)
- **Pessimistic Input Validation** to ensure data integrity and security
- **RSA Post Signing** with an option to manually verify signatures
- **CSRF Tokens** to prevent cross-site request forgery attacks
- **Strict Content Policy** to enforce secure content practices
- **Simple Post Formatting** using Markdown
- **Reverse Proxy** via Nginx for efficient routing
- **Secure Login System** for enhanced user authentication