"""
Controlador principal del autorizador MediSupply
Contiene todos los endpoints del sistema de autorización
"""
from flask_restful import Resource
from flask import request, g
from app.services.auth_service import KeycloakAuthService
import logging

logger = logging.getLogger(__name__)


class HealthCheckView(Resource):
    """Health check básico del autorizador"""
    
    def get(self):
        """
        Health check básico del servicio
        GET /authorizer/ping
        """
        return {
            "status": "ok",
            "message": "pong",
            "service": "MediSupply Authorizer Backend"
        }, 200


class AuthHealthView(Resource):
    """Health check con verificación de Keycloak"""
    
    def get(self):
        """
        Health check del servicio de autorización con verificación de Keycloak
        GET /auth/health
        """
        try:
            # Verificar conectividad con Keycloak
            auth_service = KeycloakAuthService()
            public_key = auth_service.get_public_key()
            
            if public_key:
                return {
                    'status': 'healthy',
                    'service': 'MediSupply Authorizer',
                    'keycloak_connection': 'ok',
                    'message': 'Servicio funcionando correctamente'
                }, 200
            else:
                return {
                    'status': 'unhealthy',
                    'service': 'MediSupply Authorizer',
                    'keycloak_connection': 'error',
                    'message': 'No se puede conectar con Keycloak'
                }, 503
                
        except Exception as e:
            logger.error(f"Error en health check: {e}")
            return {
                'status': 'unhealthy',
                'service': 'MediSupply Authorizer',
                'error': str(e)
            }, 500


class ProviderView(Resource):
    """Controlador para crear proveedores (endpoint protegido)"""
    
    def post(self):
        """
        Crear nuevo proveedor
        POST /provider
        Requiere rol: Administrador
        """
        try:
            user_info = g.user
            
            logger.info(f"Usuario {user_info.get('username')} creando nuevo proveedor")
            
            # Simular creación de proveedor
            new_provider = {
                "id": 1,
                "name": "Nuevo Proveedor",
                "email": "nuevo@example.com",
                "status": "activo",
                "created_by": user_info.get('username')
            }
            
            return {
                "message": "Proveedor creado exitosamente",
                "provider": new_provider
            }, 201
            
        except Exception as e:
            logger.error(f"Error al crear proveedor: {e}")
            return {
                "error": "Error interno del servidor"
            }, 500
