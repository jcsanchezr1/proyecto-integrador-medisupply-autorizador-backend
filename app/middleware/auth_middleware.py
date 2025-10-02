"""
Middleware
"""
from flask import request, jsonify
import logging
from app.config.settings import get_config

logger = logging.getLogger(__name__)
config = get_config()


class AuthMiddleware:
    """
    Middleware simplificado - solo para endpoints públicos
    """
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicializa el middleware con la aplicación Flask"""
        app.before_request(self.before_request)
    
    def before_request(self):
        """Se ejecuta antes de cada petición - solo para endpoints públicos"""
        from flask import current_app
        
        # Verificar si el endpoint es público
        if request.path in config.PUBLIC_ENDPOINTS:
            return None
        
        # Verificar si es un endpoint del autorizador
        secured_endpoints = current_app.config.get('SECURED_ENDPOINTS', {})
        for endpoint_path in secured_endpoints.keys():
            if request.path.startswith(endpoint_path):
                # Si es un endpoint del autorizador, la validación se hace en el controlador
                return None
        
        # Para cualquier otro endpoint, devolver 404
        logger.warning(f"Endpoint no encontrado: {request.method} {request.path}")
        return jsonify({
            'error': 'Endpoint no encontrado',
            'message': f'La ruta {request.path} no está configurada'
        }), 404
