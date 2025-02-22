from fastapi import Query,Depends
from pydantic import BaseModel,Field, field_validator
from typing import Optional,List,Dict
from pydantic_core.core_schema import ValidationInfo


# Request Model

class AddMultipleImagesRequest(BaseModel) : 
    paths : List[str]


# Response Model 
class GetImagesResponse(BaseModel) : 
    success : bool
    message: str 
    data : dict

class ErrorResponse(BaseModel) :
    success: bool = False
    message: str
    error: str

class AddMultipleImagesResponse(BaseModel) : 
    data : int
    message : str
    success : bool