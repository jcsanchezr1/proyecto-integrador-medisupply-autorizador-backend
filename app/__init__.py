"""
Aplicación principal del sistema de autenticación MediSupply
"""
import os
import logging
from flask import Flask
from flask_restful import Api
from flask_cors import CORS
from app.config.settings import get_config
from app.middleware.auth_middleware import AuthMiddleware

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_app():
    """Factory function para crear la aplicación Flask"""
    
    app = Flask(__name__)
    
    # Cargar configuración
    config = get_config()
    app.config.from_object(config)
    
    # Configurar CORS
    cors = CORS(app)
    
    # Configurar middleware de autorización
    auth_middleware = AuthMiddleware(app)
    
    # Configurar rutas
    configure_routes(app)
    
    logger.info(f"Aplicación {config.APP_NAME} v{config.APP_VERSION} iniciada")
    logger.info(f"Keycloak configurado: {config.KEYCLOAK_SERVER_URL}/realms/{config.KEYCLOAK_REALM}")
    
    return app


def configure_routes(app):
    """Configura las rutas de la aplicación"""
    from .controllers.authorizer_controller import (
        HealthCheckView, 
        AuthHealthView, 
        ProviderView
    )
    
    api = Api(app)
    
    # Endpoints públicos (no requieren autenticación)
    api.add_resource(HealthCheckView, '/authorizer/ping')
    api.add_resource(AuthHealthView, '/auth/health')
    
    
    # Endpoints protegidos (requieren autenticación y roles específicos)
    api.add_resource(ProviderView, '/provider')