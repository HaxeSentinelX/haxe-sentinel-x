from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)
class IncidentDB(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    risk_score = Column(Integer)
    severity = Column(String)
    threats = Column(String)