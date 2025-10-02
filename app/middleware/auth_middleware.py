"""
Middleware de autorización para interceptar y validar peticiones
"""
from flask import request, jsonify, g
from functools import wraps
import logging
from app.services.auth_service import KeycloakAuthService
from app.config.settings import get_config

logger = logging.getLogger(__name__)
config = get_config()


def require_auth(f):
    """
    Decorador para requerir autenticación en endpoints
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar si el endpoint es público
        endpoint = f"{request.method} {request.path}"
        if request.path in config.PUBLIC_ENDPOINTS:
            return f(*args, **kwargs)
        
        # Obtener token del header Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            logger.warning(f"Petición sin token de autorización a {endpoint}")
            return jsonify({
                'error': 'Token de autorización requerido',
                'message': 'Debe proporcionar un token JWT válido en el header Authorization'
            }), 401
        
        # Verificar formato del header
        if not auth_header.startswith('Bearer '):
            logger.warning(f"Formato de token inválido en petición a {endpoint}")
            return jsonify({
                'error': 'Formato de token inválido',
                'message': 'El token debe estar en formato: Bearer <token>'
            }), 401
        
        # Extraer token
        token = auth_header.split(' ')[1]
        
        # Validar token con Keycloak
        auth_service = KeycloakAuthService()
        token_payload = auth_service.validate_token(token)
        
        if not token_payload:
            logger.warning(f"Token inválido en petición a {endpoint}")
            return jsonify({
                'error': 'Token inválido',
                'message': 'El token JWT proporcionado no es válido o ha expirado'
            }), 401
        
        # Verificar roles para el endpoint
        required_roles = config.ENDPOINT_ROLES.get(endpoint)
        if required_roles:
            user_roles = auth_service.get_user_roles(token_payload)
            if not auth_service.has_required_role(user_roles, required_roles):
                logger.warning(f"Usuario sin permisos para {endpoint}. Roles del usuario: {user_roles}, Roles requeridos: {required_roles}")
                return jsonify({
                    'error': 'Acceso denegado',
                    'message': f'No tiene permisos para acceder a este endpoint. Roles requeridos: {required_roles}',
                    'user_roles': user_roles
                }), 403
        
        # Almacenar información del usuario en el contexto de Flask
        g.user = auth_service.get_user_info(token_payload)
        g.token_payload = token_payload
        
        logger.info(f"Petición autorizada para usuario {g.user.get('username')} a {endpoint}")
        return f(*args, **kwargs)
    
    return decorated_function


def auth_required():
    """
    Decorador alternativo que se puede usar directamente en las rutas
    """
    def decorator(f):
        return require_auth(f)
    return decorator


class AuthMiddleware:
    """
    Middleware de autorización que se puede usar como before_request
    """
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicializa el middleware con la aplicación Flask"""
        app.before_request(self.before_request)
    
    def before_request(self):
        """Se ejecuta antes de cada petición"""
        # Verificar si el endpoint es público
        if request.path in config.PUBLIC_ENDPOINTS:
            return None
        
        # Obtener token del header Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            logger.warning(f"Petición sin token de autorización a {request.method} {request.path}")
            return jsonify({
                'error': 'Token de autorización requerido',
                'message': 'Debe proporcionar un token JWT válido en el header Authorization'
            }), 401
        
        # Verificar formato del header
        if not auth_header.startswith('Bearer '):
            logger.warning(f"Formato de token inválido en petición a {request.method} {request.path}")
            return jsonify({
                'error': 'Formato de token inválido',
                'message': 'El token debe estar en formato: Bearer <token>'
            }), 401
        
        # Extraer token
        token = auth_header.split(' ')[1]
        
        # Validar token con Keycloak
        auth_service = KeycloakAuthService()
        token_payload = auth_service.validate_token(token)
        
        if not token_payload:
            logger.warning(f"Token inválido en petición a {request.method} {request.path}")
            return jsonify({
                'error': 'Token inválido',
                'message': 'El token JWT proporcionado no es válido o ha expirado'
            }), 401
        
        # Verificar roles para el endpoint
        endpoint = f"{request.method} {request.path}"
        required_roles = config.ENDPOINT_ROLES.get(endpoint)
        if required_roles:
            user_roles = auth_service.get_user_roles(token_payload)
            if not auth_service.has_required_role(user_roles, required_roles):
                logger.warning(f"Usuario sin permisos para {endpoint}. Roles del usuario: {user_roles}, Roles requeridos: {required_roles}")
                return jsonify({
                    'error': 'Acceso denegado',
                    'message': f'No tiene permisos para acceder a este endpoint. Roles requeridos: {required_roles}',
                    'user_roles': user_roles
                }), 403
        
        # Almacenar información del usuario en el contexto de Flask
        g.user = auth_service.get_user_info(token_payload)
        g.token_payload = token_payload
        
        logger.info(f"Petición autorizada para usuario {g.user.get('username')} a {endpoint}")
        return None
