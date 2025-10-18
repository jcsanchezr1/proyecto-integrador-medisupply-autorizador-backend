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
        
        # Obtener configuraciones de endpoints
        secured_endpoints = current_app.config.get('SECURED_ENDPOINTS', {})
        public_external_endpoints = current_app.config.get('PUBLIC_EXTERNAL_ENDPOINTS', {})
        
        # Buscar el mejor match (prefijo más largo) en ambos diccionarios
        best_secured_match = None
        best_secured_length = 0
        best_public_match = None
        best_public_length = 0
        
        # Buscar coincidencia en endpoints públicos externos
        for endpoint_path, endpoint_config in public_external_endpoints.items():
            if request.path.startswith(endpoint_path):
                # Verificar si el método HTTP coincide
                configured_method = endpoint_config.get('method', 'ALL')
                if (configured_method == 'ALL' or 
                    configured_method.upper() == request.method.upper() or 
                    request.method == 'OPTIONS'):
                    # Guardar el match más largo
                    if len(endpoint_path) > best_public_length:
                        best_public_match = endpoint_path
                        best_public_length = len(endpoint_path)
        
        # Buscar coincidencia en endpoints seguros
        for endpoint_path, endpoint_config in secured_endpoints.items():
            if request.path.startswith(endpoint_path):
                # Verificar si el método HTTP coincide
                configured_method = endpoint_config.get('method', 'ALL')
                if (configured_method == 'ALL' or 
                    configured_method.upper() == request.method.upper() or 
                    request.method == 'OPTIONS'):
                    # Guardar el match más largo
                    if len(endpoint_path) > best_secured_length:
                        best_secured_match = endpoint_path
                        best_secured_length = len(endpoint_path)
        
        # Priorizar el match más largo (más específico)
        # Si ambos tienen match, el más largo gana
        if best_public_length > best_secured_length:
            # Es un endpoint público externo (sin autenticación)
            logger.info(f"Endpoint público: {request.method} {request.path}")
            return None
        elif best_secured_match:
            # Es un endpoint seguro (con autenticación)
            logger.info(f"Endpoint seguro: {request.method} {request.path}")
            return None
        elif best_public_match:
            # Es un endpoint público externo (sin autenticación)
            logger.info(f"Endpoint público: {request.method} {request.path}")
            return None
        
        # Para cualquier otro endpoint, devolver 404
        logger.warning(f"Endpoint no encontrado: {request.method} {request.path}")
        return jsonify({
            'error': 'Endpoint no encontrado',
            'message': f'La ruta {request.path} no está configurada'
        }), 404
