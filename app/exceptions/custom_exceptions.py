"""
Excepciones personalizadas para el sistema autorizador
"""

class ValidationError(Exception):
    """Excepción para errores de validación"""
    pass


class DatabaseError(Exception):
    """Excepción para errores de base de datos"""
    pass


class ServiceError(Exception):
    """Excepción base para errores de servicios"""
    pass