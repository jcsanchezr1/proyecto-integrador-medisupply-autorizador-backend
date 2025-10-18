"""
Pruebas unitarias para el middleware de autenticación
"""
import unittest
import sys
import os
from unittest.mock import patch, Mock

# Agregar el directorio padre al path para importar la app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.middleware.auth_middleware import AuthMiddleware
from app import create_app


class TestAuthMiddleware(unittest.TestCase):
    """Pruebas para AuthMiddleware"""
    
    def setUp(self):
        """Configuración antes de cada prueba"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.middleware = AuthMiddleware(self.app)
        self.client = self.app.test_client()
    
    def test_middleware_initialization(self):
        """Prueba que el middleware se inicializa correctamente"""
        self.assertIsNotNone(self.middleware)
        self.assertIsNotNone(self.middleware.app)
    
    def test_public_endpoint_bypasses_middleware(self):
        """Prueba que los endpoints públicos internos no pasan por el middleware"""
        response = self.client.get('/authorizer/ping')
        
        # El endpoint público interno debe funcionar sin problemas
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), "pong")
    
    def test_secured_endpoint_with_options_passes_middleware(self):
        """Prueba que los endpoints seguros con OPTIONS pasan por el middleware"""
        response = self.client.options('/inventory/products')
        
        # OPTIONS en endpoint seguro debe pasar por el middleware
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
    
    def test_public_external_endpoint_with_options_passes_middleware(self):
        """Prueba que los endpoints públicos externos con OPTIONS pasan por el middleware"""
        response = self.client.options('/auth/token')
        
        # OPTIONS en endpoint público externo debe pasar por el middleware
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
    
    def test_unknown_endpoint_returns_404_from_middleware(self):
        """Prueba que endpoints desconocidos retornan 404 desde el middleware"""
        response = self.client.get('/unknown/endpoint')
        
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertIn('Endpoint no encontrado', data['error'])
    
    def test_unknown_endpoint_with_options_returns_404_from_middleware(self):
        """Prueba que endpoints desconocidos con OPTIONS retornan 404 desde el middleware"""
        response = self.client.options('/unknown/endpoint')
        
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertIn('Endpoint no encontrado', data['error'])
    
    def test_secured_endpoint_with_get_passes_middleware(self):
        """Prueba que endpoints seguros con GET pasan por el middleware"""
        response = self.client.get('/inventory/products')
        
        # GET en endpoint seguro debe pasar por el middleware (retornará 401 por falta de auth)
        self.assertEqual(response.status_code, 401)
    
    def test_public_external_endpoint_with_post_passes_middleware(self):
        """Prueba que endpoints públicos externos con POST pasan por el middleware"""
        response = self.client.post('/auth/token')
        
        # POST en endpoint público externo debe pasar por el middleware
        # Puede retornar 200 (si el servicio está disponible) o error de conexión
        self.assertIn(response.status_code, [200, 500, 503, 504])
    
    def test_middleware_handles_all_http_methods_for_configured_endpoints(self):
        """Prueba que el middleware maneja todos los métodos HTTP para endpoints configurados"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        endpoints = ['/inventory/products', '/auth/token', '/auth/ping']
        
        for endpoint in endpoints:
            for method in methods:
                with self.subTest(endpoint=endpoint, method=method):
                    response = self.client.open(endpoint, method=method)
                    
                    # Todos los métodos deben pasar por el middleware (no 405)
                    self.assertNotEqual(response.status_code, 405)
    
    def test_middleware_logs_unknown_endpoints(self):
        """Prueba que el middleware registra endpoints desconocidos"""
        with patch('app.middleware.auth_middleware.logger') as mock_logger:
            response = self.client.get('/unknown/endpoint')
            
            # Verificar que se registró el warning
            mock_logger.warning.assert_called()
            self.assertIn('Endpoint no encontrado', str(mock_logger.warning.call_args))
    
    def test_middleware_allows_options_for_all_configured_endpoints(self):
        """Prueba que el middleware permite OPTIONS para todos los endpoints configurados"""
        from app.config.settings import get_config
        config = get_config()
        
        # Obtener todos los endpoints configurados
        all_endpoints = []
        all_endpoints.extend(config.SECURED_ENDPOINTS.keys())
        all_endpoints.extend(config.PUBLIC_EXTERNAL_ENDPOINTS.keys())
        
        for endpoint in all_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.options(endpoint)
                
                # OPTIONS debe pasar por el middleware y retornar 200
                self.assertEqual(response.status_code, 200)
    
    def test_middleware_before_request_returns_none_for_configured_endpoints(self):
        """Prueba que before_request retorna None para endpoints configurados"""
        with self.app.test_request_context('/inventory/products'):
            result = self.middleware.before_request()
            
            # Debería retornar None para permitir que continúe el procesamiento
            self.assertIsNone(result)
    
    def test_middleware_before_request_returns_404_for_unknown_endpoints(self):
        """Prueba que before_request retorna 404 para endpoints desconocidos"""
        with self.app.test_request_context('/unknown'):
            result = self.middleware.before_request()
            
            # Debería retornar una respuesta 404
            self.assertIsNotNone(result)
            self.assertEqual(result[1], 404)  # status_code


if __name__ == '__main__':
    unittest.main()
