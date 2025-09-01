# NexAPI - FastAPI Authentication Service

A production-ready FastAPI authentication API with JWT tokens, PostgreSQL, Redis, and comprehensive configuration management.

## 🚀 Features

- **User Authentication**: Registration, login with form/JSON support
- **JWT Token Management**: Secure access tokens with configurable expiration
- **Refresh Token System**: HTTP-only cookies for enhanced security
- **Password Security**: bcrypt hashing with salt rounds
- **Database Integration**: PostgreSQL with connection pooling
- **Caching Layer**: Redis for session management and performance
- **CORS Support**: Configurable cross-origin resource sharing
- **Environment Configuration**: JSON-based config with environment overrides
- **Modular Architecture**: Clean separation of concerns following FastAPI best practices
- **Type Safety**: Full typing annotations with Pydantic validation
- **Structured Logging**: Using structlog for better observability

## 📁 Project Structure

```
auth-api/
├── app/
│   ├── core/                    # Core functionality
│   │   ├── configuration.py     # Configuration management with dataclasses
│   │   ├── dependencies.py      # Dependency injection providers
│   │   ├── exceptions.py        # Custom exception handlers
│   │   └── security.py          # JWT, password hashing, token utilities
│   ├── models/                  # Pydantic schemas
│   │   └── user.py             # User request/response models
│   ├── router/                  # API route handlers
│   │   └── auth.py             # Authentication endpoints
│   └── service/                 # Business logic layer
│       └── user.py             # User service with database operations
├── main.py                      # FastAPI application entry point
├── requirements.txt             # Python dependencies
├── config.development.json      # Development configuration
├── .env.example                # Environment variables template
├── .gitignore                  # Git ignore rules
└── README.md                   # Project documentation
```

## 🛠️ Installation

### Prerequisites
- Python 3.11+
- PostgreSQL 13+
- Redis 6+

### Setup

1. **Clone the repository:**
```bash
git clone https://github.com/chisanucha-plum/auth-api.git
cd auth-api
```

2. **Create virtual environment:**
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Configure environment:**
```bash
copy .env.example .env
# Edit .env with your configuration
```

5. **Setup database:**
```bash
# Create PostgreSQL database
createdb auth_api_db
```

6. **Run the application:**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## 📡 API Endpoints

### Authentication Routes (`/auth`)

| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| `POST` | `/auth/register` | Register new user | ❌ |
| `POST` | `/auth/login` | Login with form data | ❌ |
| `POST` | `/auth/login-json` | Login with JSON payload | ❌ |
| `GET` | `/auth/me` | Get current user profile | ✅ |
| `GET` | `/auth/users` | List all users | ✅ |

### API Documentation
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## ⚙️ Configuration

### Environment Variables (`.env`)
```bash
SITE=development                    # Configuration profile
POSTGRES_HOST=localhost             # Database host
POSTGRES_PORT=5432                  # Database port
POSTGRES_USER=your_db_user          # Database username
POSTGRES_PASSWORD=your_password     # Database password
POSTGRES_DATABASE=auth_api_db       # Database name
REDIS_HOST=localhost                # Redis host
REDIS_PORT=6379                     # Redis port
SECRET_KEY=your-secret-key          # JWT signing key
```

### Configuration Files
- `config.development.json` - Development settings
- `config.production.json` - Production settings (create as needed)
- `config.testing.json` - Testing settings (create as needed)

### Key Configuration Sections
- **Application**: Host, title, version, redirect settings
- **CORS**: Cross-origin policies and allowed origins
- **PostgreSQL**: Database connection parameters
- **Redis**: Cache and session store configuration
- **JWT**: Token signing, algorithm, expiration settings
- **Cookies**: Refresh token cookie configuration

## 🔧 Development

### Architecture Principles
- **Dependency Injection**: Using FastAPI's `Depends()` for clean service injection
- **Single Responsibility**: Each module focuses on one concern
- **Type Safety**: Full typing with Pydantic models and Python type hints
- **Configuration as Code**: JSON-based configuration with dataclass parsing
- **Layered Architecture**: Router → Service → Model separation

### Adding New Features
1. **Create Pydantic models** in `app/models/`
2. **Implement business logic** in `app/service/`
3. **Add route handlers** in `app/router/`
4. **Register routes** in `main.py`

### Code Style
- Follow PEP 8 and FastAPI conventions
- Use type hints for all functions
- Implement proper error handling
- Add comprehensive docstrings

## 🧪 Testing

```bash
# Run tests (when implemented)
pytest

# Run with coverage
pytest --cov=app
```

## 🚢 Deployment

### Docker (Recommended)
```dockerfile
# Create Dockerfile for containerized deployment
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Production Considerations
- Use environment-specific configuration files
- Set `COOKIE_SECURE=true` for HTTPS
- Configure proper CORS origins
- Use strong `SECRET_KEY`
- Enable database connection pooling
- Set up proper logging and monitoring

## 📝 License

This project is licensed under the MIT License.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

For questions or issues, please open an issue