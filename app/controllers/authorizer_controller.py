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
    
    def _handle_options_request(self, full_path: str):
        """
        Maneja peticiones OPTIONS (CORS Preflight) para endpoints externos
        
        Args:
            full_path: Ruta completa de la petición
            
        Returns:
            Respuesta OPTIONS con headers CORS apropiados
        """
        from flask import current_app, make_response
        
        # Verificar si es un endpoint seguro configurado
        secured_endpoints = current_app.config.get('SECURED_ENDPOINTS', {})
        public_endpoints = current_app.config.get('PUBLIC_EXTERNAL_ENDPOINTS', {})
        
        # Buscar coincidencia en endpoints seguros
        matched_secured = None
        for endpoint_path in secured_endpoints.keys():
            if full_path.startswith(endpoint_path):
                matched_secured = endpoint_path
                break
        
        # Buscar coincidencia en endpoints públicos
        matched_public = None
        for endpoint_path in public_endpoints.keys():
            if full_path.startswith(endpoint_path):
                matched_public = endpoint_path
                break
        
        # Si no hay coincidencia, devolver 404
        if not matched_secured and not matched_public:
            return {
                'error': 'Endpoint no encontrado',
                'message': f'La ruta {full_path} no está configurada'
            }, 404
        
        # Crear respuesta OPTIONS con headers CORS
        response = make_response('', 200)
        
        # Headers CORS estándar
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Max-Age'] = '3600'
        
        # Si hay headers específicos en la petición, incluirlos en la respuesta
        requested_headers = request.headers.get('Access-Control-Request-Headers')
        if requested_headers:
            response.headers['Access-Control-Allow-Headers'] = requested_headers
        
        logger.info(f"OPTIONS request handled for {full_path}")
        return response
    
    def _handle_request(self, path: str = None):
        """
        Maneja cualquier petición HTTP al autorizador
        
        Args:
            path: Ruta específica después del endpoint base
        """
        try:
            # Obtener la ruta completa
            full_path = request.path
            
            # MANEJO ESPECIAL PARA OPTIONS (CORS Preflight)
            if request.method == 'OPTIONS':
                return self._handle_options_request(full_path)
            
            # PRIMERO: Verificar si es un endpoint seguro (con autenticación)
            endpoint_config = self.authorizer_service.get_endpoint_config(full_path, request.method)
            
            if endpoint_config:
                # Es un endpoint seguro, requiere autenticación
                # La lógica de autenticación continúa más abajo
                pass
            else:
                # SEGUNDO: Si no es seguro, verificar si es un endpoint público
                public_endpoint_config = self.authorizer_service.get_public_endpoint_config(full_path, request.method)
                
                if public_endpoint_config:
                    # Es un endpoint público, redirigir sin autenticación
                    endpoint_path = None
                    from flask import current_app
                    public_endpoints = current_app.config.get('PUBLIC_EXTERNAL_ENDPOINTS', {})
                    # Seleccionar la coincidencia de prefijo más larga
                    matched_prefix = ''
                    for configured_path in public_endpoints.keys():
                        if full_path.startswith(configured_path) and len(configured_path) > len(matched_prefix):
                            matched_prefix = configured_path
                    if matched_prefix:
                        endpoint_path = full_path[len(matched_prefix):]
                    
                    # Redirigir la petición al servicio de destino (sin autenticación)
                    response_data, status_code = self.authorizer_service.forward_public_request(
                        public_endpoint_config, endpoint_path or ''
                    )
                    
                    return response_data, status_code
            
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
            
            # Extraer la ruta específica después del endpoint base usando prefijo más largo
            endpoint_path = None
            from flask import current_app
            secured_endpoints = current_app.config.get('SECURED_ENDPOINTS', {})
            matched_prefix = ''
            for configured_path in secured_endpoints.keys():
                if full_path.startswith(configured_path) and len(configured_path) > len(matched_prefix):
                    matched_prefix = configured_path
            if matched_prefix:
                endpoint_path = full_path[len(matched_prefix):]
            
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
