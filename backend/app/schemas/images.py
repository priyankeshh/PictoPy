from fastapi import Query,Depends
from pydantic import BaseModel,Field, field_validator
from typing import Optional,List,Dict,Union
from pydantic_core.core_schema import ValidationInfo


# Request Model

class AddMultipleImagesRequest(BaseModel) : 
    paths : List[str]

class DeleteImageRequest(BaseModel) : 
    path : str

class DeleteMultipleImagesRequest(BaseModel) : 
    paths : List[str]


class AddFolderRequest(BaseModel) : 
    folder_path : str

class GenerateThumbnailsRequest(BaseModel) : 
    folder_paths : List[str]




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


class DeleteImageResponse(BaseModel) : 
    data : str
    message : str
    success : bool

class DeleteMultipleImagesResponse(BaseModel) : 
    data : List[str]
    message : str
    success : bool

class ImageDataResponse(BaseModel) : 
    images: Dict[str, str]  # Mapping image paths to class names or "None"
    folder_path: str

class GetAllImageObjectsResponse(BaseModel) : 
    success: bool
    message: str
    data: ImageDataResponse

class ClassIDsResponse(BaseModel):
    success: bool
    message: str
    data: Union[List[int], str]

class AddFolderResponse(BaseModel) : 
    data: int
    message: str
    success: bool

class FailedPathResponse(BaseModel):
    folder_path: str
    error: str
    message: str
    file: Optional[str] = None

class GenerateThumbnailsResponse(BaseModel) : 
    success : bool
    message : str 
    failed_paths : Optional[List[FailedPathResponse]] = None