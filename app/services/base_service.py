"""
Servicio base - Estructura para implementar lógica de negocio
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Any


class BaseService(ABC):
    """Servicio base con operaciones comunes"""
    
    @abstractmethod
    def create(self, **kwargs) -> Any:
        """Crea una nueva entidad"""
        pass
    
    @abstractmethod
    def get_by_id(self, entity_id: str) -> Optional[Any]:
        """Obtiene una entidad por ID"""
        pass
    
    @abstractmethod
    def get_all(self, limit: Optional[int] = None, offset: int = 0) -> List[Any]:
        """Obtiene todas las entidades"""
        pass
    
    @abstractmethod
    def update(self, entity_id: str, **kwargs) -> Optional[Any]:
        """Actualiza una entidad"""
        pass
    
    @abstractmethod
    def delete(self, entity_id: str) -> bool:
        """Elimina una entidad"""
        pass
    
    @abstractmethod
    def validate_business_rules(self, **kwargs) -> None:
        """Valida las reglas de negocio específicas"""
        pass