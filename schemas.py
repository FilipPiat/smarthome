from pydantic import BaseModel, Field
import datetime as _dt


class DeviceBase(BaseModel):
    name: str = Field(min_length=1)
    description: str = Field(max_length=100)
    state: int = Field(gt=-1, lt=101)
    type: str = Field(min_length=1)


class DeviceCreate(DeviceBase):
    pass


class Device(DeviceBase):
    id: int
    owner_id: int
    last_update: _dt.datetime

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    hashed_password: str

    class Config:
        orm_mode = True


class User(UserBase):
    id: int

    class Config:
        orm_mode = True
