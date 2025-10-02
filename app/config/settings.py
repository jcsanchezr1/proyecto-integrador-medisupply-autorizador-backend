"""
Configuración de la aplicación - Estructura para manejar configuraciones
"""
import os


class Config:
    """Configuración base de la aplicación"""
    
    # Configuración básica
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', '8080'))
    
    # Configuración de la aplicación
    APP_NAME = 'MediSupply Authorizer Backend'
    APP_VERSION = '1.0.0'
    
    # Configuración de Keycloak
    KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080')
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'medisupply-realm')
    KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'medisupply-client')
    
    # Configuración de JWT
    JWT_ALGORITHM = 'RS256'
    JWT_ISSUER = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}"
    
    # Endpoints que no requieren autenticación
    PUBLIC_ENDPOINTS = ['/authorizer/ping']
    
    # Variables de entorno para URLs de servicios
    POKEMON_SERVICE_URL = os.getenv('POKEMON_SERVICE_URL', 'https://pokeapi.co')
    
    # Configuración de endpoints seguros (Autorizador)
    SECURED_ENDPOINTS = {
        '/pokemon': {
            'target_url': f"{POKEMON_SERVICE_URL}/api/v2/pokemon",
            'method': 'ALL',  # ALL significa todos los métodos HTTP
            'required_roles': ['Administrador']
        }
    }


class DevelopmentConfig(Config):
    """Configuración para desarrollo"""
    DEBUG = True


class ProductionConfig(Config):
    """Configuración para producción"""
    DEBUG = False


def get_config():
    """Retorna la configuración según el entorno"""
    env = os.getenv('FLASK_ENV', 'development').lower()
    
    if env == 'production':
        return ProductionConfig()
    else:
        return DevelopmentConfig()