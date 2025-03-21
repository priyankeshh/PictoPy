from pydantic import BaseModel
from typing import List, Dict

# Request Model


class TestRouteRequest(BaseModel):
    path: str


class AddSingleImageRequest(BaseModel):
    path: str


# Response Model


class DetectionData(BaseModel):
    class_ids: List[str | None]  # List of detected class IDs
    detected_classes: List[str | None]  # List of class names


class TestRouteResponse(BaseModel):
    success: bool
    message: str
    data: DetectionData


class GetImagesResponse(BaseModel):
    success: bool
    message: str
    data: Dict[str, List[str]]


class AddSingleImageResponse(BaseModel):
    success: bool
    message: str
    data: Dict[str, str]


class ErrorResponse(BaseModel):
    success: bool = False
    message: str
    error: str


class TestImageResponse(BaseModel):
    success: bool
    message: str
