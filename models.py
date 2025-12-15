from sqlalchemy import Column, Integer, String, Text, Date, DateTime, ForeignKey
from sqlalchemy.sql import func
from db_engine import Base


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, index=True)
    login = Column(String(100), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    passport_series = Column(String(10))
    passport_number = Column(String(20))
    registration_address = Column(String(255))
    birth_date = Column(Date)
    position_id = Column(Integer)
    department = Column(String(100))
    role = Column(String(50))
    work_phone = Column(String(20))
    personal_phone = Column(String(20))
    email = Column(String(100))


class UserToken(Base):
    __tablename__ = "user_tokens"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id", ondelete="CASCADE"), nullable=False, index=True)
    access_token = Column(Text, nullable=False, index=True)
    refresh_token = Column(Text, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
