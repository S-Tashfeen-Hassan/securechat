from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import time

class Hello(BaseModel):
    type: str = "hello"
    certPem: str
    nonce: Optional[str] = None

class DH_Client(BaseModel):
    type: str = "dh_client"
    A: str

class DH_Server(BaseModel):
    type: str = "dh_server"
    B: str
    sig: str

class Login(BaseModel):
    type: str = "login"
    username: str
    password: str

class Register(BaseModel):
    type: str = "register"
    username: str
    email: str
    password: str

class Chat_Msg(BaseModel):
    type: str = "msg"
    seq: int
    iv: str
    ct: str
    mac: str

def json_en(obj):
    if hasattr(obj, "dict"):
        j = obj.dict()
    elif isinstance(obj, dict):
        j = obj
    else:
        raise TypeError("json_en accepts pydantic models or dicts")
    return json.dumps(j).encode("utf-8")

def json_de(bs: bytes):
    return json.loads(bs.decode("utf-8"))

def now_ms():
    return int(time.time() * 1000)
