from fastapi import FastAPI
from api.routes import router

app = FastAPI(
    title="The Inspector",
    description="AI-Driven Zero Trust Asset Admission System",
    version="1.0.0"
)

app.include_router(router)