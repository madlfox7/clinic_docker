import os

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from db import ensure_schema, seed_clinic, seed_users, seed_work_schedule
from routes_admin import router as admin_router
from routes_auth import router as auth_router
from routes_booking import router as booking_router



SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret-change-me")





app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
app.include_router(auth_router)
app.include_router(booking_router)
app.include_router(admin_router)


@app.on_event("startup")
def on_start():
    ensure_schema()
    seed_users()
    seed_clinic()
    seed_work_schedule()
