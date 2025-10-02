"""
Modelo base para todas las entidades del sistema
"""
from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseModel(ABC):
    """Modelo base abstracto para todas las entidades"""
    
    def __init__(self, **kwargs):
        """Inicializa el modelo con los datos proporcionados"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el modelo a diccionario"""
        pass
    
    @abstractmethod
    def validate(self) -> None:
        """Valida los datos del modelo"""
        pass
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"