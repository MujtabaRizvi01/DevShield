from pydantic import BaseModel

class CodePayload(BaseModel):
    filename: str
    code: str
