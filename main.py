from fastapi import FastAPI, HTTPException, status, Form, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict
from db_engine import get_db, init_db
import auth.crud as crud
from auth.schemas import TokenResponse, RefreshRequest, UserResponse
from auth.utils import create_tokens, verify_token, hash_password
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    yield


security = HTTPBearer()
app = FastAPI(title="Gateway Service", version="1.0.0", lifespan=lifespan)


async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: AsyncSession = Depends(get_db)
) -> Dict:
    token = credentials.credentials
    payload = verify_token(token)
    print(payload)
    if not payload or "error" in payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Not an access token")

    db_token = await crud.get_token_by_access(db, token)
    if not db_token:
        raise HTTPException(status_code=401, detail="Token revoked")

    return payload


@app.post("/login", response_model=TokenResponse)
async def login(
        employee_login: str = Form(...),
        password: str = Form(...),
        db: AsyncSession = Depends(get_db)
):
    user = await crud.authenticate_employee(db, employee_login, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {
        "sub": user.login,
        "user_id": user.id,
        "role": user.role,
    }

    tokens = create_tokens(token_data)

    await crud.save_user_tokens(db, user.id, tokens["access_token"], tokens["refresh_token"])

    return TokenResponse(**tokens)


@app.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
        request: RefreshRequest,
        db: AsyncSession = Depends(get_db)
):
    payload = verify_token(request.refresh_token)
    if not payload or "error" in payload:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Not a refresh token")

    token_record = await crud.get_token_by_refresh(db, request.refresh_token)
    if not token_record:
        raise HTTPException(status_code=400, detail="Refresh token not found")

    user = await crud.get_employee_by_login(db, payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token_data = {
        "sub": user.login,
        "user_id": user.id,
        "role": user.role,
    }

    new_tokens = create_tokens(token_data)

    await crud.update_user_tokens(
        db,
        token_record.id,
        new_tokens["access_token"],
        new_tokens["refresh_token"]
    )

    return TokenResponse(**new_tokens)


@app.post("/logout", response_model=Dict)
async def logout(
        payload: dict = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
):
    await crud.revoke_user_tokens(db, payload["user_id"])
    return {"message": "Successfully logged out"}


@app.get("/me", response_model=UserResponse)
async def get_current_user_info(
        payload: dict = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
):
    user = await crud.get_employee_by_id(db, payload["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserResponse(
        login=user.login,
        role=user.role,
        full_name=user.full_name,
    )


@app.post("/register", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def register_employee(
        employee_login: str = Form(...),
        password: str = Form(...),
        role: str = Form(""),
        full_name: str = Form(""),
        db: AsyncSession = Depends(get_db)
):
    existing = await crud.get_employee_by_login(db, employee_login)
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    new_user = await crud.create_employee(
        db,
        login=employee_login,
        password_hash=hash_password(password),
        role=role,
        full_name=full_name
    )

    return {
        "message": "Employee registered successfully",
        "login": new_user.login
    }
