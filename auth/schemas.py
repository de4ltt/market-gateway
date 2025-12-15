from pydantic import BaseModel, ConfigDict
from typing import Optional


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    login: str
    role: Optional[str] = None
    full_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
