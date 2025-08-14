import json
from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Load from config file
    def __init__(self):
        super().__init__()
        config_file = Path("config.development.json")
        if config_file.exists():
            with open(config_file, "r") as f:
                config_data = json.load(f)
                
            # App settings
            app_config = config_data.get("app", {})
            self.app_name = app_config.get("name", "Auth API")
            self.app_version = app_config.get("version", "1.0.0")
            self.debug = app_config.get("debug", False)
            
            # Server settings
            server_config = config_data.get("server", {})
            self.host = server_config.get("host", "0.0.0.0")
            self.port = server_config.get("port", 8000)
            
            # Security settings
            security_config = config_data.get("security", {})
            self.secret_key = security_config.get("secret_key", "change-me")
            self.algorithm = security_config.get("algorithm", "HS256")
            self.access_token_expire_minutes = security_config.get("access_token_expire_minutes", 30)
            
            # Database settings
            database_config = config_data.get("database", {})
            self.database_url = database_config.get("url", "sqlite:///./auth.db")
    
    app_name: str = "Auth API"
    app_version: str = "1.0.0"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    secret_key: str = "change-me"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    database_url: str = "sqlite:///./auth.db"

settings = Settings()
