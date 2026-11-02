from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import Role, User

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(value: str) -> str:
    return pwd.hash(value)


def verify_password(value: str, hashed: str) -> bool:
    return pwd.verify(value, hashed)


def token_for(user: User, expire_minutes: int | None = None) -> str:
    issued_at = datetime.now(timezone.utc)
    exp = issued_at + timedelta(minutes=expire_minutes or settings.token_expire_minutes)
    return jwt.encode({"sub": user.id, "role": user.role.value, "iat": issued_at, "exp": exp}, settings.app_secret, algorithm="HS256")


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, settings.app_secret, algorithms=["HS256"])
        user_id = payload.get("sub")
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="登录已失效") from exc
    user = db.get(User, user_id)
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="用户不可用")
    issued_at = payload.get("iat")
    if issued_at and user.password_changed_at:
        changed_at = user.password_changed_at if user.password_changed_at.tzinfo else user.password_changed_at.replace(tzinfo=timezone.utc)
        if datetime.fromtimestamp(int(issued_at), timezone.utc) < changed_at.replace(microsecond=0):
            raise HTTPException(status_code=401, detail="密码已变更，请重新登录")
    return user


def require(*roles: Role):
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="没有操作权限")
        return user

    return dependency

