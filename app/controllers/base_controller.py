"""
Controlador base - Estructura para implementar controladores REST
"""
from flask_restful import Resource
from typing import Dict, Any, Tuple


class BaseController(Resource):
    """Controlador base con operaciones comunes"""
    
    def handle_exception(self, e: Exception) -> Tuple[Dict[str, Any], int]:
        """Maneja excepciones y retorna respuesta JSON apropiada"""
        # Implementar manejo centralizado de excepciones
        return {"error": str(e)}, 500
    
    def success_response(self, data: Any = None, message: str = "Success", status_code: int = 200) -> Tuple[Dict[str, Any], int]:
        """Retorna respuesta de éxito"""
        response = {"message": message}
        if data is not None:
            response["data"] = data
        return response, status_code
    
    def error_response(self, message: str, status_code: int = 400) -> Tuple[Dict[str, Any], int]:
        """Retorna respuesta de error"""
        return {"error": message}, status_code