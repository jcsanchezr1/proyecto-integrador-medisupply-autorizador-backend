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
        """Se ejecuta antes de cada petición - maneja endpoints públicos y seguros"""
        from flask import current_app
        
        # Verificar si el endpoint es público (sin redirección)
        if request.path in config.PUBLIC_ENDPOINTS:
            return None
        
        # PRIMERO: Verificar si es un endpoint seguro (con autenticación)
        secured_endpoints = current_app.config.get('SECURED_ENDPOINTS', {})
        for endpoint_path, endpoint_config in secured_endpoints.items():
            if request.path.startswith(endpoint_path):
                # Verificar si el método HTTP coincide
                configured_method = endpoint_config.get('method', 'ALL')
                if configured_method == 'ALL' or configured_method.upper() == request.method.upper():
                    # Si es un endpoint seguro, la validación se hace en el controlador
                    return None
        
        # SEGUNDO: Verificar si es un endpoint público externo (sin autenticación)
        public_external_endpoints = current_app.config.get('PUBLIC_EXTERNAL_ENDPOINTS', {})
        for endpoint_path, endpoint_config in public_external_endpoints.items():
            if request.path.startswith(endpoint_path):
                # Verificar si el método HTTP coincide
                configured_method = endpoint_config.get('method', 'ALL')
                if configured_method == 'ALL' or configured_method.upper() == request.method.upper():
                    # Si es un endpoint público externo, la redirección se hace en el controlador
                    return None
        
        # Para cualquier otro endpoint, devolver 404
        logger.warning(f"Endpoint no encontrado: {request.method} {request.path}")
        return jsonify({
            'error': 'Endpoint no encontrado',
            'message': f'La ruta {request.path} no está configurada'
        }), 404
