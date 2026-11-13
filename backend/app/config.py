import os
from pydantic import BaseModel

class Settings(BaseModel):
    PORT: int = int(os.getenv("PORT", "8000"))
    PHISHDETECT_DB: str = os.getenv("PHISHDETECT_DB", "phishdetect.db")

settings = Settings()
