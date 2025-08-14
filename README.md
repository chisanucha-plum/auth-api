# Auth API

A FastAPI-based authentication API with JWT tokens.

## Features

- User registration and login
- JWT token-based authentication
- Password hashing with bcrypt
- RESTful API design
- Modular project structure

## Project Structure

```
app/
├── core/
│   ├── config.py          # Configuration settings
│   ├── dependencies.py    # Dependency injection
│   ├── exceptions.py      # Custom exceptions
│   └── security.py        # Security utilities
├── models/
│   └── user.py           # Pydantic models
├── router/
│   └── auth.py           # Authentication routes
└── service/
    └── user.py           # User business logic
```

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
uvicorn main:app --reload
```

## API Endpoints

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login with form data
- `POST /auth/login-json` - Login with JSON payload
- `GET /auth/me` - Get current user info (protected)
- `GET /auth/users` - Get all users (protected)

## Configuration

Edit `config.development.json` to configure the application settings.

## Development

The API follows a modular structure with clear separation of concerns:

- **router/**: Contains route handlers (API endpoints)
- **service/**: Contains business logic
- **model/**: Contains Pydantic models for request/response validation
- **core/**: Contains configuration, dependencies, exceptions, and security utilities
