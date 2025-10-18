"""
Pruebas unitarias para la creación de la aplicación usando unittest
"""
import unittest
import sys
import os

# Agregar el directorio padre al path para importar la app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import create_app


class TestAppCreation(unittest.TestCase):
    """Pruebas para la creación de la aplicación usando unittest"""
    
    def test_create_app_returns_flask_app(self):
        """Prueba que create_app retorna una instancia de Flask"""
        app = create_app()
        
        self.assertIsNotNone(app)
        self.assertTrue(hasattr(app, 'config'))
        self.assertTrue(hasattr(app, 'route'))
    
    def test_app_has_cors_enabled(self):
        """Prueba que CORS está habilitado"""
        app = create_app()
        
        # Verificar que CORS está configurado en la aplicación
        self.assertIsNotNone(app)
        self.assertTrue(hasattr(app, 'after_request'))
    
    def test_app_has_secret_key(self):
        """Prueba que la aplicación tiene SECRET_KEY configurada"""
        app = create_app()
        
        self.assertIn('SECRET_KEY', app.config)
        self.assertIsNotNone(app.config['SECRET_KEY'])
    
    def test_app_has_keycloak_config(self):
        """Prueba que la aplicación tiene configuración de Keycloak"""
        app = create_app()
        
        self.assertIn('KEYCLOAK_SERVER_URL', app.config)
        self.assertIn('KEYCLOAK_REALM', app.config)
        self.assertIn('KEYCLOAK_CLIENT_ID', app.config)
        self.assertIn('JWT_ALGORITHM', app.config)
        self.assertIn('JWT_ISSUER', app.config)
    
    def test_app_has_secured_endpoints_config(self):
        """Prueba que la aplicación tiene configuración de endpoints seguros"""
        app = create_app()
        
        self.assertIn('SECURED_ENDPOINTS', app.config)
        self.assertIsInstance(app.config['SECURED_ENDPOINTS'], dict)
        self.assertIn('/inventory/products', app.config['SECURED_ENDPOINTS'])
    
    def test_app_has_public_endpoints_config(self):
        """Prueba que la aplicación tiene configuración de endpoints públicos"""
        app = create_app()
        
        self.assertIn('PUBLIC_ENDPOINTS', app.config)
        self.assertIsInstance(app.config['PUBLIC_ENDPOINTS'], list)
        self.assertIn('/authorizer/ping', app.config['PUBLIC_ENDPOINTS'])


if __name__ == '__main__':
    unittest.main()
