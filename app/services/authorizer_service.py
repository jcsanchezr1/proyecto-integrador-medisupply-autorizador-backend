"""
Servicio del Autorizador para redirigir peticiones a servicios de destino
Incluye funcionalidad de autenticación con Keycloak
"""
import requests
import logging
import jwt
from typing import Dict, Optional, Tuple, List
from flask import request, g, current_app
import base64
import json

logger = logging.getLogger(__name__)


class AuthorizerService:
    """Servicio para manejar el proxy/autorizador de peticiones con autenticación Keycloak"""
    
    def __init__(self):
        self.server_url = current_app.config.get('KEYCLOAK_SERVER_URL')
        self.realm = current_app.config.get('KEYCLOAK_REALM')
        self.client_id = current_app.config.get('KEYCLOAK_CLIENT_ID')
        self.jwt_issuer = current_app.config.get('JWT_ISSUER')
        self.jwt_algorithm = current_app.config.get('JWT_ALGORITHM')
        self._public_key = None
    
    def validate_request(self, endpoint_config: Dict, user_roles: list) -> Tuple[bool, str]:
        """
        Valida si el usuario tiene permisos para acceder al endpoint
        
        Args:
            endpoint_config: Configuración del endpoint desde settings
            user_roles: Roles del usuario autenticado
            
        Returns:
            Tuple (is_valid, error_message)
        """
        required_roles = endpoint_config.get('required_roles', [])
        
        if not required_roles:
            return True, ""
        
        if not self.has_required_role(user_roles, required_roles):
            return False, f"Acceso denegado. Roles requeridos: {', '.join(required_roles)}"
        
        return True, ""
    
    def forward_request(self, endpoint_config: Dict, path: str) -> Tuple[Dict, int]:
        """
        Redirige la petición al servicio de destino
        
        Args:
            endpoint_config: Configuración del endpoint
            path: Ruta específica después del endpoint base
            
        Returns:
            Tuple (response_data, status_code)
        """
        try:
            target_url = endpoint_config['target_url']
            method = request.method
            
            # Construir URL completa
            if path and path != '/':
                full_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
            else:
                full_url = target_url
            
            # Preparar headers
            headers = dict(request.headers)
            
            # Remover headers que no deben ser reenviados
            headers_to_remove = ['Host', 'Content-Length', 'Content-Type']
            for header in headers_to_remove:
                headers.pop(header, None)
            
            # Agregar información del usuario autenticado
            if hasattr(g, 'user') and g.user:
                headers['X-User-ID'] = g.user.get('user_id', '')
                headers['X-Username'] = g.user.get('username', '')
                headers['X-User-Roles'] = ','.join(g.user.get('roles', []))
            
            # Preparar datos de la petición
            request_data, files = self._prepare_request_data()
            
            # Determinar si enviar como JSON o form-data (asegurar booleano)
            is_json_request = bool(request.is_json or (not files and request_data is not None))
            
            # Realizar petición al servicio de destino
            response = requests.request(
                method=method,
                url=full_url,
                headers=headers,
                json=request_data if is_json_request else None,
                data=request_data if not is_json_request else None,
                files=files if files else None,
                params=request.args,
                timeout=30
            )
            
            # Preparar respuesta
            response_data = {}
            try:
                response_data = response.json()
            except ValueError:
                response_data = {'data': response.text}
            
            logger.info(f"Authorizer: {method} {full_url} -> {response.status_code}")
            
            return response_data, response.status_code
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout al conectar con {target_url}")
            return {
                'error': 'Timeout del servicio de destino',
                'message': 'El servicio no respondió en el tiempo esperado'
            }, 504
            
        except requests.exceptions.ConnectionError:
            logger.error(f"Error de conexión con {target_url}")
            return {
                'error': 'Servicio no disponible',
                'message': 'No se pudo conectar con el servicio de destino'
            }, 503
            
        except Exception as e:
            logger.error(f"Error inesperado en autorizador: {e}")
            return {
                'error': 'Error interno del autorizador',
                'message': 'Error inesperado al procesar la petición'
            }, 500
    
    def get_endpoint_config(self, path: str, method: str = None) -> Optional[Dict]:
        """
        Obtiene la configuración del endpoint basado en la ruta y método HTTP
        
        Args:
            path: Ruta de la petición
            method: Método HTTP de la petición
            
        Returns:
            Configuración del endpoint o None si no existe
        """
        from flask import current_app
        
        secured_endpoints = current_app.config.get('SECURED_ENDPOINTS', {})
        
        # Buscar coincidencia exacta primero
        if path in secured_endpoints:
            config = secured_endpoints[path]
            # Verificar si el método HTTP coincide
            if self._method_matches(config.get('method', 'ALL'), method):
                return config
        
        # Buscar coincidencia por prefijo
        for endpoint_path, config in secured_endpoints.items():
            if path.startswith(endpoint_path):
                # Verificar si el método HTTP coincide
                if self._method_matches(config.get('method', 'ALL'), method):
                    return config
        
        return None
    
    def get_public_endpoint_config(self, path: str, method: str = None) -> Optional[Dict]:
        """
        Obtiene la configuración del endpoint público basado en la ruta y método HTTP
        
        Args:
            path: Ruta de la petición
            method: Método HTTP de la petición
            
        Returns:
            Configuración del endpoint público o None si no existe
        """
        from flask import current_app
        
        public_endpoints = current_app.config.get('PUBLIC_EXTERNAL_ENDPOINTS', {})
        
        # Buscar coincidencia exacta primero
        if path in public_endpoints:
            config = public_endpoints[path]
            # Verificar si el método HTTP coincide
            if self._method_matches(config.get('method', 'ALL'), method):
                return config
        
        # Buscar coincidencia por prefijo
        for endpoint_path, config in public_endpoints.items():
            if path.startswith(endpoint_path):
                # Verificar si el método HTTP coincide
                if self._method_matches(config.get('method', 'ALL'), method):
                    return config
        
        return None
    
    def is_authorizer_endpoint(self, path: str, method: str = None) -> bool:
        """
        Verifica si la ruta es un endpoint del autorizador
        
        Args:
            path: Ruta de la petición
            method: Método HTTP de la petición
            
        Returns:
            True si es un endpoint del autorizador
        """
        return self.get_endpoint_config(path, method) is not None
    
    def is_public_endpoint(self, path: str, method: str = None) -> bool:
        """
        Verifica si la ruta es un endpoint público externo
        
        Args:
            path: Ruta de la petición
            method: Método HTTP de la petición
            
        Returns:
            True si es un endpoint público externo
        """
        return self.get_public_endpoint_config(path, method) is not None
    
    def _method_matches(self, configured_method: str, request_method: str) -> bool:
        """
        Verifica si el método HTTP de la petición coincide con el configurado
        
        Args:
            configured_method: Método configurado en el endpoint
            request_method: Método HTTP de la petición
            
        Returns:
            True si el método coincide
        """
        # Si no se provee método (compatibilidad con llamadas antiguas/tests), considerar como coincidencia
        if not request_method:
            return True
        
        # Si está configurado como 'ALL', acepta cualquier método
        if configured_method == 'ALL':
            return True
        
        # Comparación exacta (case insensitive)
        return configured_method.upper() == request_method.upper()
    
    def _prepare_request_data(self) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Prepara los datos de la petición para reenviar, manejando diferentes tipos de contenido
        
        Returns:
            Tuple (request_data, files) donde:
            - request_data: Datos a enviar (dict, bytes, o None)
            - files: Archivos a enviar (dict o None)
        """
        from flask import request
        
        request_data = None
        files = None
        
        # Verificar si es JSON
        if request.is_json:
            request_data = request.get_json()
        
        # Verificar si es form-data o multipart
        elif request.form or request.files:
            # Preparar datos de formulario
            form_data = {}
            files_data = {}
            
            # Procesar campos de formulario
            for key, value in request.form.items():
                form_data[key] = value
            
            # Procesar archivos
            for key, file in request.files.items():
                if file and file.filename:
                    # Para multipart/form-data, usar el objeto file directamente
                    # requests manejará la lectura del archivo automáticamente
                    files_data[key] = (file.filename, file.stream, file.content_type or 'application/octet-stream')
            
            if files_data:
                # Si hay archivos, usar files y data por separado
                files = files_data
                request_data = form_data if form_data else None
            else:
                # Si solo hay form-data sin archivos, convertir a JSON
                request_data = form_data
        
        # Verificar si hay datos raw
        elif request.data:
            request_data = request.data
        
        return request_data, files
    
    def forward_public_request(self, endpoint_config: Dict, path: str) -> Tuple[Dict, int]:
        """
        Redirige la petición pública al servicio de destino (sin autenticación)
        
        Args:
            endpoint_config: Configuración del endpoint público
            path: Ruta específica después del endpoint base
            
        Returns:
            Tuple (response_data, status_code)
        """
        try:
            target_url = endpoint_config['target_url']
            method = request.method
            
            # Construir URL completa
            if path and path != '/':
                full_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
            else:
                full_url = target_url
            
            # Preparar headers (sin información de usuario)
            headers = dict(request.headers)
            
            # Remover headers que no deben ser reenviados
            headers_to_remove = ['Host', 'Content-Length', 'Content-Type']
            for header in headers_to_remove:
                headers.pop(header, None)
            
            # Preparar datos de la petición
            request_data, files = self._prepare_request_data()
            
            # Log para debugging
            logger.info(f"Forwarding public request: {method} {full_url}")
            logger.info(f"Request data: {request_data}")
            logger.info(f"Files: {files}")
            logger.info(f"Is JSON: {request.is_json}")
            logger.info(f"Content-Type: {request.content_type}")
            logger.info(f"Form data: {dict(request.form)}")
            logger.info(f"Files in request: {list(request.files.keys())}")
            logger.info(f"Headers being sent: {headers}")
            
            # Determinar si enviar como JSON o form-data (asegurar booleano)
            is_json_request = bool(request.is_json or (not files and request_data is not None))
            logger.info(f"Is JSON request: {is_json_request}")
            
            # Realizar petición al servicio de destino
            response = requests.request(
                method=method,
                url=full_url,
                headers=headers,
                json=request_data if is_json_request else None,
                data=request_data if not is_json_request else None,
                files=files if files else None,
                params=request.args,
                timeout=30
            )
            
            # Preparar respuesta
            response_data = {}
            try:
                response_data = response.json()
            except ValueError:
                response_data = {'data': response.text}
            
            logger.info(f"Public Authorizer: {method} {full_url} -> {response.status_code}")
            try:
                resp_headers = (
                    dict(response.headers)
                    if hasattr(response, 'headers') and hasattr(response.headers, 'items')
                    else {}
                )
                logger.info(f"Response headers: {resp_headers}")
            except Exception:
                logger.info("Response headers: <unavailable>")
            logger.info(f"Response data: {response_data}")
            
            return response_data, response.status_code
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout al conectar con {target_url}")
            return {
                'error': 'Timeout del servicio de destino',
                'message': 'El servicio no respondió en el tiempo esperado'
            }, 504
            
        except requests.exceptions.ConnectionError:
            logger.error(f"Error de conexión con {target_url}")
            return {
                'error': 'Servicio no disponible',
                'message': 'No se pudo conectar con el servicio de destino'
            }, 503
            
        except Exception as e:
            logger.error(f"Error inesperado en autorizador público: {e}")
            return {
                'error': 'Error interno del autorizador',
                'message': 'Error inesperado al procesar la petición'
            }, 500
    
    # Métodos de autenticación con Keycloak
    def get_public_key(self, kid: str = None) -> Optional[str]:
        """Obtiene la clave pública de Keycloak para validar JWT"""
        try:
            url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/certs"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            jwks = response.json()
            if 'keys' not in jwks or not jwks['keys']:
                logger.error("No se encontraron claves públicas en Keycloak")
                return None
            
            # Buscar la clave con el kid específico, o usar la primera disponible
            key_to_use = None
            if kid:
                for key in jwks['keys']:
                    if key.get('kid') == kid:
                        key_to_use = key
                        break
            
            if not key_to_use:
                key_to_use = jwks['keys'][0]
                logger.warning(f"No se encontró clave con kid {kid}, usando la primera disponible")
            
            return self._jwk_to_pem(key_to_use)
                
        except requests.RequestException as e:
            logger.error(f"Error al obtener clave pública de Keycloak: {e}")
            return None
        except Exception as e:
            logger.error(f"Error inesperado al obtener clave pública: {e}")
            return None
    
    def _jwk_to_pem(self, jwk: Dict) -> str:
        """Convierte una clave JWK a formato PEM"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        # Extraer componentes de la clave RSA
        n = base64.urlsafe_b64decode(jwk['n'] + '==')
        e = base64.urlsafe_b64decode(jwk['e'] + '==')
        
        # Convertir a enteros
        n_int = int.from_bytes(n, 'big')
        e_int = int.from_bytes(e, 'big')
        
        # Crear clave RSA
        public_key = rsa.RSAPublicNumbers(e_int, n_int).public_key()
        
        # Serializar a PEM
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return pem.decode('utf-8')
    
    def validate_token(self, token: str) -> Optional[Dict]:
        """
        Valida un token JWT de Keycloak
        
        Args:
            token: Token JWT a validar
            
        Returns:
            Dict con la información del token si es válido, None si no
        """
        try:
            # Extraer el header del token para obtener el kid
            header_data = token.split('.')[0]
            # Agregar padding si es necesario
            header_data += '=' * (4 - len(header_data) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_data))
            kid = header.get('kid')
            
            # Obtener clave pública usando el kid específico
            public_key = self.get_public_key(kid)
            if not public_key:
                logger.error("No se pudo obtener la clave pública de Keycloak")
                return None
            
            # Decodificar y validar el token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[self.jwt_algorithm],
                issuer=self.jwt_issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": False,
                    "verify_aud": False
                }
            )
            
            # Verificar que el token es para el cliente correcto
            if 'azp' in payload and payload['azp'] != self.client_id:
                logger.warning(f"Token no es para el cliente correcto. Esperado: {self.client_id}, Obtenido: {payload.get('azp')}")
                return None
            
            if 'aud' in payload:
                audience = payload['aud']
                valid_audiences = [self.client_id, 'account', 'medisupply-app']  # Audiences válidos
                
                if isinstance(audience, list):
                    if not any(aud in valid_audiences for aud in audience):
                        logger.warning(f"Token audience no incluye ningún audience válido. Esperado uno de: {valid_audiences}, Obtenido: {audience}")
                        return None
                elif audience not in valid_audiences:
                    logger.warning(f"Token audience no es válido. Esperado uno de: {valid_audiences}, Obtenido: {audience}")
                    return None
            
            logger.info(f"Token validado exitosamente para usuario: {payload.get('preferred_username', 'unknown')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expirado")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token inválido: {e}")
            return None
        except Exception as e:
            logger.error(f"Error inesperado al validar token: {e}")
            return None
    
    def get_user_roles(self, token_payload: Dict) -> List[str]:
        """
        Extrae los roles del usuario del payload del token
        
        Args:
            token_payload: Payload decodificado del token JWT
            
        Returns:
            Lista de roles del usuario
        """
        roles = []
        
        # Obtener roles del realm
        if 'realm_access' in token_payload and 'roles' in token_payload['realm_access']:
            realm_roles = token_payload['realm_access']['roles']
            roles.extend(realm_roles)
        
        # Obtener roles específicos del cliente
        if 'resource_access' in token_payload and self.client_id in token_payload['resource_access']:
            client_roles = token_payload['resource_access'][self.client_id].get('roles', [])
            roles.extend(client_roles)
        
        return roles
    
    def has_required_role(self, user_roles: List[str], required_roles: List[str]) -> bool:
        """
        Verifica si el usuario tiene alguno de los roles requeridos
        
        Args:
            user_roles: Roles del usuario
            required_roles: Roles requeridos para el endpoint
            
        Returns:
            True si el usuario tiene al menos uno de los roles requeridos
        """
        return any(role in user_roles for role in required_roles)
    
    def get_user_info(self, token_payload: Dict) -> Dict:
        """
        Extrae información del usuario del payload del token
        
        Args:
            token_payload: Payload decodificado del token JWT
            
        Returns:
            Diccionario con información del usuario
        """
        return {
            'user_id': token_payload.get('sub'),
            'username': token_payload.get('preferred_username'),
            'email': token_payload.get('email'),
            'name': token_payload.get('name'),
            'roles': self.get_user_roles(token_payload)
        }
