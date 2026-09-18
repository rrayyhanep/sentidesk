"""Pydantic request and response contracts."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict, EmailStr, field_validator


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    username: str | None = Field(default=None, min_length=2, max_length=80)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token: str | None = None
    token_type: str = "bearer"
    verification_required: bool = False
    verification_token: str | None = None
    verification_code: str | None = None

class EmailVerification(BaseModel):
    email: EmailStr | None = None
    token: str | None = Field(default=None, min_length=16)
    code: str | None = Field(default=None, min_length=6, max_length=6)

    @field_validator("code")
    @classmethod
    def numeric_code(cls, value):
        if value is not None and not value.isdigit():
            raise ValueError("verification code must contain only digits")
        return value

class ProviderConnection(BaseModel):
    platform: Literal["gmail", "whatsapp", "instagram"]

class ProviderMessage(BaseModel):
    sender: str = Field(min_length=1, max_length=320)
    content: str = Field(min_length=1, max_length=10000)
    external_id: str | None = Field(default=None, max_length=255)
    timestamp: datetime | None = None

class Message(BaseModel):
    model_config = ConfigDict(extra="ignore")
    role: Literal["customer", "agent", "system"] = "customer"
    content: str = Field(min_length=1, max_length=10000)
    timestamp: datetime | None = None

class ConversationCreate(BaseModel):
    customer_name: str = Field(min_length=1, max_length=120)
    email: str | None = None
    messages: list[Message] = Field(default_factory=list)
    priority: Literal["low", "medium", "high", "critical"] = "medium"

class ConversationUpdate(BaseModel):
    status: Literal["open", "pending", "resolved", "closed"] | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None

class AnalysisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=30000)

class BulkAnalysisRequest(BaseModel):
    messages: list[Message] = Field(default_factory=list, min_length=1, max_length=100)

class ContractAnalysisRequest(BaseModel):
    conversation_id: str
    text: str = Field(min_length=1, max_length=30000)

class ContractBatchRequest(BaseModel):
    conversations: list[ContractAnalysisRequest] = Field(min_length=1, max_length=100)
