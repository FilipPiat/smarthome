from fastapi import FastAPI, HTTPException, Depends
from typing import List
import fastapi.security as _security
from sqlalchemy.orm import Session
import services
import schemas
import models

app = FastAPI(title="Smart home")


@app.get("/us")
def show_user(db: Session = Depends(services.get_db)):
    return db.query(models.Users).all()


@app.post("/api/users")
async def create_user(user: schemas.UserCreate, db: Session = Depends(services.get_db)):
    db_user = await services.get_user_by_email(user.email, db)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already used")

    user = await services.create_user(user, db)

    return await services.create_token(user)


@app.post("/api/token")
async def generate_token(
    form_data: _security.OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(services.get_db),
):
    user = await services.authenticate_user(form_data.username, form_data.password, db)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid Credentials")

    return await services.create_token(user)


@app.get("/api/users/me", response_model=schemas.User)
async def get_user(user: schemas.User = Depends(services.get_current_user)):
    return user


@app.post("/api/devices", response_model=schemas.Device)
async def create_device(device: schemas.DeviceCreate,
                        user: schemas.User = Depends(services.get_current_user),
                        db: Session = Depends(services.get_db)):
    return await services.create_device(user=user, db=db, device=device)


@app.get("/api/devices", response_model=List[schemas.Device])
async def get_devices(user: schemas.User = Depends(services.get_current_user),
                        db: Session = Depends(services.get_db)):
    return await services.get_devices(user=user, db=db)


@app.get("/api/devices/{device_id}", status_code=200)
async def get_device(device_id: int, user: schemas.User = Depends(services.get_current_user),
                        db: Session = Depends(services.get_db)):
    return await services.get_device(device_id, user, db)


@app.delete("/api/devices/{device_id}", status_code=204)
async def delete_device(
    device_id: int,
    user: schemas.User = Depends(services.get_current_user),
    db: Session = Depends(services.get_db),
):
    await services.delete_device(device_id, user, db)
    return {"message", "Successfully Deleted"}


@app.put("/api/devices/{device_id}", status_code=200)
async def update_device(
    device_id: int,
    device: schemas.DeviceCreate,
    user: schemas.User = Depends(services.get_current_user),
    db: Session = Depends(services.get_db),
):
    await services.update_device(device_id, device, user, db)
    return {"message", "Successfully Updated"}


@app.get("/api")
async def root():
    return {"message": "Smart Home Manager"}
