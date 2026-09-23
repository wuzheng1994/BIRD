from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
from dotenv import load_dotenv


class config(BaseSettings):

    DASHSCOPE_API_KEY: Optional[str] = None
    
    LANGSMITH_API_KEY: Optional[str] = None
    LANGSMITH_TRACING: Optional[bool] = True
    LANGSMITH_ENDPOINT: Optional[str] = None
    LANGSMITH_PROJECT: Optional[str] = None

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
        env_file=Path(__file__).resolve().parent.joinpath(".env"),
        env_file_encoding="utf-8",
    )

config = config()

_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_env_path)