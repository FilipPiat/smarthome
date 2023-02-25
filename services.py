import models
import database
import schemas
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException
import fastapi.security as _security
import passlib.hash as _hash
import jwt
import datetime as _dt

oauth2schema = _security.OAuth2PasswordBearer(tokenUrl="/api/token")

DEVICE_TYPES = {
    1: "switch",
    2: "heater",
    3: "percentage value"
}

JWT_SECRET = "myjwtsecret"


def create_database():
    return database.Base.metadata.create_all(bind=database.engine)


def get_db():
    try:
        db = database.SessionLocal()
        yield db
    finally:
        db.close()


async def get_user_by_email(email: str, db: Session):
    return db.query(models.Users).filter(models.Users.email == email).first()


async def create_user(user: schemas.UserCreate, db: Session):
    user_obj = models.Users(
        # email=user.email, hashed_password=_hash.bcrypt.hash(user.hashed_password)
    )
    user_obj.email = user.email
    user_obj.hashed_password = _hash.bcrypt.hash(user.hashed_password)
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    return user_obj


async def authenticate_user(email: str, password: str, db: Session):
    user = await get_user_by_email(db=db, email=email)

    if not user:
        return False

    if not user.verify_password(password):
        return False

    return user


async def create_token(user: models.Users):
    user_obj = schemas.User.from_orm(user)

    token = jwt.encode(user_obj.dict(), JWT_SECRET)

    return dict(access_token=token, token_type="bearer")


async def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2schema),
):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = db.query(models.Users).get(payload["id"])
    except:
        raise HTTPException(
            status_code=401, detail="Invalid Email or Password"
        )

    return schemas.User.from_orm(user)


async def create_device(user: schemas.User, db: Session, device: schemas.DeviceCreate):
    device = models.Devices(**device.dict(), owner_id=user.id)
    if device.type == DEVICE_TYPES[1]:
        if device.state > 1:
            device.state = 1
        if device.state == 1:
           device.description = "ON"
        elif device.state == 0:
           device.description = "OFF"
    elif device.type == DEVICE_TYPES[2]:
        device.description = str(device.state) + " ◦C"
    elif device.type == DEVICE_TYPES[3]:
        if device.state>0:
            device.description = "Opened in " + str(device.state) + "%"
        else:
            device.description = "Closed"
    
    db.add(device)
    db.commit()
    db.refresh(device)
    return schemas.Device.from_orm(device)


async def get_devices(user: schemas.User, db: Session):
    devices = db.query(models.Devices).filter_by(owner_id=user.id)

    return list(map(schemas.Device.from_orm, devices))


async def device_selector(device_id: int, user: schemas.User, db: Session):
    device = db.query(models.Devices).filter_by(owner_id=user.id).filter(models.Devices.id == device_id).first()

    if device is None:
        raise HTTPException(status_code=404, detail="Device does not exist.")

    return device


async def get_device(device_id: int, user: schemas.User, db: Session):
    device = await device_selector(device_id=device_id, user=user, db=db)

    return schemas.Device.from_orm(device)


async def delete_device(device_id: int, user: schemas.User, db: Session):
    device = await device_selector(device_id, user, db)

    db.delete(device)
    db.commit()


async def update_device(device_id: int, device: schemas.DeviceCreate, user: schemas.User, db: Session):
    device_db = await device_selector(device_id, user, db)
    dev = db.query(models.Devices).filter_by(owner_id=user.id).filter(models.Devices.id == device_id).first()
    device_db.state = device.state
    if dev.type == DEVICE_TYPES[1]:
        if device.state > 1:
            device.state = 1
        if device.state == 1:
           device_db.description = "ON"
        elif device.state == 0:
           device_db.description = "OFF"
    elif dev.type == DEVICE_TYPES[2]:
        device_db.description = str(device.state) + " ◦C"
    elif dev.type == DEVICE_TYPES[3]:
        if device.state>0:
            device_db.description = "Opened in " + str(device.state) + "%"
        else:
            device_db.description = "Closed"
    device_db.last_update = _dt.datetime.now()

    db.commit()
    db.refresh(device_db)

    return schemas.Device.from_orm(device_db)

