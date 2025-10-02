"""
Controlador para health check del sistema
"""
from flask_restful import Resource


class HealthCheckView(Resource):
    """Controlador para health check"""
    
    def get(self):
        """
        Usado para verificar el estado del servicio.
        """
        return "pong", 200