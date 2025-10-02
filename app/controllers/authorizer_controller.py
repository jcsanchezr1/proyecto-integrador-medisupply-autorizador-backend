"""
Controlador del Autorizador para manejar todas las rutas dinámicas
"""
from flask_restful import Resource
from flask import request, g
from app.services.authorizer_service import AuthorizerService
import logging

logger = logging.getLogger(__name__)


class AuthorizerView(Resource):
    """Controlador genérico que maneja todas las rutas del autorizador"""
    
    def __init__(self):
        self.authorizer_service = AuthorizerService()
    
    def _handle_request(self, path: str = None):
        """
        Maneja cualquier petición HTTP al autorizador
        
        Args:
            path: Ruta específica después del endpoint base
        """
        try:
            # Obtener la ruta completa
            full_path = request.path
            
            # Obtener configuración del endpoint
            endpoint_config = self.authorizer_service.get_endpoint_config(full_path)
            
            if not endpoint_config:
                return {
                    'error': 'Endpoint no encontrado',
                    'message': f'La ruta {full_path} no está configurada en el autorizador'
                }, 404
            
            # Verificar si el endpoint requiere autenticación
            required_roles = endpoint_config.get('required_roles', [])
            
            if required_roles:
                # Obtener token del header Authorization
                auth_header = request.headers.get('Authorization')
                if not auth_header:
                    return {
                        'error': 'No autorizado',
                        'message': 'Se requiere autenticación para acceder a este endpoint'
                    }, 401
                
                # Verificar formato del header
                if not auth_header.startswith('Bearer '):
                    return {
                        'error': 'Formato de token inválido',
                        'message': 'El token debe estar en formato: Bearer <token>'
                    }, 401
                
                # Extraer token
                token = auth_header.split(' ')[1]
                
                # Validar token con Keycloak
                token_payload = self.authorizer_service.validate_token(token)
                
                if not token_payload:
                    return {
                        'error': 'Token inválido',
                        'message': 'El token JWT proporcionado no es válido o ha expirado'
                    }, 401
                
                # Obtener roles del usuario
                user_roles = self.authorizer_service.get_user_roles(token_payload)
                
                # Validar roles
                is_valid, error_message = self.authorizer_service.validate_request(
                    endpoint_config, user_roles
                )
                
                if not is_valid:
                    return {
                        'error': 'Acceso denegado',
                        'message': error_message
                    }, 403
                
                # Almacenar información del usuario en el contexto de Flask
                g.user = self.authorizer_service.get_user_info(token_payload)
                g.token_payload = token_payload
            
            # Extraer la ruta específica después del endpoint base
            endpoint_path = None
            from flask import current_app
            secured_endpoints = current_app.config.get('SECURED_ENDPOINTS', {})
            for configured_path in secured_endpoints.keys():
                if full_path.startswith(configured_path):
                    endpoint_path = full_path[len(configured_path):]
                    break
            
            # Redirigir la petición al servicio de destino
            response_data, status_code = self.authorizer_service.forward_request(
                endpoint_config, endpoint_path or ''
            )
            
            return response_data, status_code
            
        except Exception as e:
            logger.error(f"Error en autorizador controller: {e}")
            return {
                'error': 'Error interno del servidor',
                'message': 'Error inesperado al procesar la petición'
            }, 500
    
    def get(self, path: str = None):
        """Maneja peticiones GET"""
        return self._handle_request(path)
    
    def post(self, path: str = None):
        """Maneja peticiones POST"""
        return self._handle_request(path)
    
    def put(self, path: str = None):
        """Maneja peticiones PUT"""
        return self._handle_request(path)
    
    def delete(self, path: str = None):
        """Maneja peticiones DELETE"""
        return self._handle_request(path)
    
    def patch(self, path: str = None):
        """Maneja peticiones PATCH"""
        return self._handle_request(path)
    
    def options(self, path: str = None):
        """Maneja peticiones OPTIONS"""
        return self._handle_request(path)


class AuthorizerHealthView(Resource):
    """Health check específico para el autorizador"""
    
    def get(self):
        """
        Health check del autorizador
        GET /authorizer/ping
        """
        try:
            from flask import current_app
            
            secured_endpoints = current_app.config.get('SECURED_ENDPOINTS', {})
            
            return "pong", 200
            
        except Exception as e:
            logger.error(f"Error en autorizador health check: {e}")
            return {
                'status': 'unhealthy',
                'service': 'MediSupply Authorizer',
                'error': str(e)
            }, 500
