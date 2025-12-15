from sqlalchemy import select, delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from models import Employee, UserToken
from auth.utils import verify_password


async def get_employee_by_id(db: AsyncSession, employee_id: int) -> Optional[Employee]:
    result = await db.execute(
        select(Employee).where(Employee.id == employee_id)
    )
    return result.scalar_one_or_none()


async def get_employee_by_login(db: AsyncSession, login: str) -> Optional[Employee]:
    result = await db.execute(
        select(Employee).where(Employee.login == login)
    )
    return result.scalar_one_or_none()


async def authenticate_employee(db: AsyncSession, login: str, password: str) -> Optional[Employee]:
    employee = await get_employee_by_login(db, login)
    if employee and verify_password(password, employee.password):
        return employee
    return None


async def create_employee(
    db: AsyncSession, 
    login: str, 
    password_hash: str,
    role: str,
    full_name: str = None
) -> Employee:
    employee = Employee(
        login=login,
        password=password_hash,
        role=role,
        full_name=full_name
    )
    db.add(employee)
    await db.commit()
    await db.refresh(employee)
    return employee


async def update_employee(
    db: AsyncSession,
    employee_id: int,
    **kwargs
) -> Optional[Employee]:
    await db.execute(
        update(Employee)
        .where(Employee.id == employee_id)
        .values(**kwargs)
    )
    await db.commit()
    return await get_employee_by_id(db, employee_id)


async def save_user_tokens(
    db: AsyncSession, 
    employee_id: int, 
    access_token: str, 
    refresh_token: str
) -> UserToken:
    await db.execute(
        delete(UserToken).where(UserToken.employee_id == employee_id)
    )

    user_token = UserToken(
        employee_id=employee_id,
        access_token=access_token,
        refresh_token=refresh_token
    )
    db.add(user_token)
    await db.commit()
    await db.refresh(user_token)
    return user_token


async def get_token_by_access(db: AsyncSession, access_token: str) -> Optional[UserToken]:
    result = await db.execute(
        select(UserToken).where(UserToken.access_token == access_token)
    )
    return result.scalar_one_or_none()


async def get_token_by_refresh(db: AsyncSession, refresh_token: str) -> Optional[UserToken]:
    result = await db.execute(
        select(UserToken).where(UserToken.refresh_token == refresh_token)
    )
    return result.scalar_one_or_none()


async def revoke_user_tokens(db: AsyncSession, employee_id: int) -> None:
    await db.execute(
        delete(UserToken).where(UserToken.employee_id == employee_id)
    )
    await db.commit()


async def update_user_tokens(
    db: AsyncSession,
    token_id: int,
    access_token: str,
    refresh_token: str
) -> Optional[UserToken]:
    await db.execute(
        update(UserToken)
        .where(UserToken.id == token_id)
        .values(
            access_token=access_token,
            refresh_token=refresh_token
        )
    )
    await db.commit()
    
    result = await db.execute(
        select(UserToken).where(UserToken.id == token_id)
    )
    return result.scalar_one_or_none()
