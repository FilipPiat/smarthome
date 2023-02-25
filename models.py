from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from database import Base
import datetime as _dt
import passlib.hash as _hash
from sqlalchemy.orm import relationship
import sqlalchemy.orm as _orm


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    #device = relationship("Devices", back_populates="owner")

    def verify_password(self, password: str):
        return _hash.bcrypt.verify(password, self.hashed_password)


class Devices(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String, nullable=True)
    type = Column(String)
    state = Column(Integer)
    last_update = Column(DateTime, default=_dt.datetime.now())
    owner_id = Column(Integer, ForeignKey("users.id"))

   # owner = relationship("Users", back_populates="devices")
