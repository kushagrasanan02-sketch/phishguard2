from pydantic import BaseModel

class HealthCheckResponse(BaseModel):
    status: str
    version: str
    database: str
    environment: str
