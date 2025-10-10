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
        AuthorizerView,
        AuthorizerHealthView
    )
    
    api = Api(app)
    
    # Endpoints públicos (no requieren autenticación)
    api.add_resource(AuthorizerHealthView, '/authorizer/ping')
    
    # Autorizador dinámico - captura todas las rutas configuradas
    secured_endpoints = app.config.get('SECURED_ENDPOINTS', {})
    for i, endpoint_path in enumerate(secured_endpoints.keys()):
        # Crear una clase dinámica para cada endpoint para evitar conflictos
        class_name = f"AuthorizerView{i}"
        dynamic_view = type(class_name, (AuthorizerView,), {})
        # Usar un patrón que capture cualquier ruta que comience con el endpoint
        api.add_resource(dynamic_view, f"{endpoint_path}", f"{endpoint_path}/<path:path>")
    
    # Endpoints públicos externos - captura todas las rutas públicas configuradas
    public_external_endpoints = app.config.get('PUBLIC_EXTERNAL_ENDPOINTS', {})
    for i, endpoint_path in enumerate(public_external_endpoints.keys()):
        # Crear una clase dinámica para cada endpoint público para evitar conflictos
        class_name = f"PublicAuthorizerView{i}"
        dynamic_view = type(class_name, (AuthorizerView,), {})
        # Usar un patrón que capture cualquier ruta que comience con el endpoint
        api.add_resource(dynamic_view, f"{endpoint_path}", f"{endpoint_path}/<path:path>")