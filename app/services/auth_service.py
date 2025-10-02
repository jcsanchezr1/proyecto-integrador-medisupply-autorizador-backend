"""
Servicio de autenticación con Keycloak
"""
import jwt
import requests
from typing import Dict, List, Optional
from flask import current_app
import logging

logger = logging.getLogger(__name__)


class KeycloakAuthService:
    """Servicio para autenticación con Keycloak"""
    
    def __init__(self):
        self.server_url = current_app.config.get('KEYCLOAK_SERVER_URL')
        self.realm = current_app.config.get('KEYCLOAK_REALM')
        self.client_id = current_app.config.get('KEYCLOAK_CLIENT_ID')
        self.jwt_issuer = current_app.config.get('JWT_ISSUER')
        self.jwt_algorithm = current_app.config.get('JWT_ALGORITHM')
        self._public_key = None
    
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
        import base64
        
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
            import base64
            import json
            
            # Decodificar el header del token
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
                    "verify_iss": False 
                }
            )
            
            # Verificar que el token es para el cliente correcto
            if 'azp' in payload and payload['azp'] != self.client_id:
                logger.warning(f"Token no es para el cliente correcto. Esperado: {self.client_id}, Obtenido: {payload.get('azp')}")
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expirado")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token inválido: {e}")
            logger.warning(f"Token recibido: {token}...")
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
            roles.extend(token_payload['realm_access']['roles'])
        
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
