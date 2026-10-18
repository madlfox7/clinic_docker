import os

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from routes_admin import router as admin_router
from routes_auth import router as auth_router
from routes_booking import router as booking_router
from routes_records import router as records_router
from routes_schedule import router as schedule_router



SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret-change-me")





app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
app.include_router(auth_router)
app.include_router(booking_router)
app.include_router(admin_router)
app.include_router(records_router)
app.include_router(schedule_router)
