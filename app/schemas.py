from typing import Union, Optional
from pydantic import BaseModel, Field, field_validator


class CiphertextSchema(BaseModel):
    c1: Union[int, str]
    c2: Union[int, str]

    @field_validator("c1", "c2", mode="before")
    @classmethod
    def parse_to_int(cls, v):
        if isinstance(v, str):
            try:
                return int(v)
            except ValueError:
                raise ValueError("Value must be a valid integer representation")
        return v


class NIZKProofSchema(BaseModel):
    challenge_0: Union[int, str] = Field(..., alias="challenge_0")
    challenge_1: Union[int, str] = Field(..., alias="challenge_1")
    response_0: Union[int, str]
    response_1: Union[int, str]
    A0: Union[int, str]
    B0: Union[int, str]
    A1: Union[int, str]
    B1: Union[int, str]
    challenge: Optional[Union[int, str]] = None
    type: Optional[str] = "NIZK 0 1 FS"

    model_config = {
        "populate_by_name": True
    }

    @field_validator(
        "challenge_0", "challenge_1", "response_0", "response_1",
        "A0", "B0", "A1", "B1", "challenge",
        mode="before"
    )
    @classmethod
    def parse_to_int(cls, v):
        if v is None:
            return v
        if isinstance(v, str):
            try:
                return int(v)
            except ValueError:
                raise ValueError("Value must be a valid integer representation")
        return v


class VotePayloadSchema(BaseModel):
    token: str
    ciphertext: CiphertextSchema
    proof: NIZKProofSchema


class TokenBatchSchema(BaseModel):
    count: int = Field(default=5, ge=1, le=100)
