"""
Pruebas de integración para el endpoint de health check usando unittest
"""
import unittest
import sys
import os

# Agregar el directorio padre al path para importar la app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import create_app


class TestHealthEndpoint(unittest.TestCase):
    """Pruebas de integración para el endpoint /authorizer/ping usando unittest"""
    
    def setUp(self):
        """Configuración antes de cada prueba"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
    
    def test_health_endpoint_returns_pong(self):
        """Prueba que el endpoint /authorizer/ping retorna 'pong'"""
        response = self.client.get('/authorizer/ping')
        
        self.assertEqual(response.status_code, 200)
        # El endpoint retorna JSON con "pong"
        self.assertEqual(response.get_json(), "pong")
    
    def test_health_endpoint_returns_json(self):
        """Prueba que el endpoint retorna content-type application/json"""
        response = self.client.get('/authorizer/ping')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/json')
    
    def test_health_endpoint_handles_get_method(self):
        """Prueba que el endpoint maneja correctamente el método GET"""
        response = self.client.get('/authorizer/ping')
        
        self.assertEqual(response.status_code, 200)
        # Verificar que la respuesta es exitosa
        self.assertEqual(response.get_json(), "pong")
    
    def test_health_endpoint_does_not_accept_post(self):
        """Prueba que el endpoint no acepta método POST"""
        response = self.client.post('/authorizer/ping')
        
        self.assertEqual(response.status_code, 405)  # Method Not Allowed


if __name__ == '__main__':
    unittest.main()
