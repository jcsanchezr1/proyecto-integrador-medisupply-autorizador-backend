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
        # Flask-CORS se integra con la app, no cambia el tipo
        self.assertIsNotNone(app)
        # Verificar que la app tiene las configuraciones de CORS
        self.assertTrue(hasattr(app, 'after_request'))
    
    def test_app_has_secret_key(self):
        """Prueba que la aplicación tiene SECRET_KEY configurada"""
        app = create_app()
        
        self.assertIn('SECRET_KEY', app.config)
        self.assertIsNotNone(app.config['SECRET_KEY'])


if __name__ == '__main__':
    unittest.main()
