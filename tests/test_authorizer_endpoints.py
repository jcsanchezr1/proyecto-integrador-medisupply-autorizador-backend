"""
Pruebas de integración para los endpoints del autorizador usando unittest
"""
import unittest
import sys
import os
from unittest.mock import patch, Mock

# Agregar el directorio padre al path para importar la app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import create_app


class TestAuthorizerEndpoints(unittest.TestCase):
    """Pruebas de integración para los endpoints del autorizador usando unittest"""
    
    def setUp(self):
        """Configuración antes de cada prueba"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
    
    def test_health_endpoint_returns_pong(self):
        """Prueba que el endpoint /authorizer/ping retorna 'pong'"""
        response = self.client.get('/authorizer/ping')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), "pong")
    
    def test_health_endpoint_returns_json(self):
        """Prueba que el endpoint /authorizer/ping retorna content-type application/json"""
        response = self.client.get('/authorizer/ping')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/json')
    
    def test_health_endpoint_handles_get_method(self):
        """Prueba que el endpoint /authorizer/ping maneja correctamente el método GET"""
        response = self.client.get('/authorizer/ping')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), "pong")
    
    def test_health_endpoint_does_not_accept_post(self):
        """Prueba que el endpoint /authorizer/ping no acepta método POST"""
        response = self.client.post('/authorizer/ping')
        
        self.assertEqual(response.status_code, 405)  # Method Not Allowed
    
    @patch('app.services.authorizer_service.AuthorizerService.validate_token')
    @patch('app.services.authorizer_service.AuthorizerService.get_user_roles')
    @patch('app.services.authorizer_service.AuthorizerService.validate_request')
    @patch('app.services.authorizer_service.AuthorizerService.forward_request')
    def test_inventory_products_endpoint_with_valid_token_and_roles(self, mock_forward, mock_validate_request, mock_get_roles, mock_validate_token):
        """Prueba que el endpoint /inventory/products funciona con token válido y roles correctos"""
        # Configurar mocks
        mock_validate_token.return_value = {
            'sub': 'user123',
            'preferred_username': 'testuser',
            'realm_access': {'roles': ['Administrador']}
        }
        mock_get_roles.return_value = ['Administrador']
        mock_validate_request.return_value = (True, "")
        mock_forward.return_value = ({'products': []}, 200)
        
        # Hacer petición
        response = self.client.get('/inventory/products', headers={'Authorization': 'Bearer valid_token'})
        
        # Verificar resultado
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {'products': []})
    
    def test_inventory_products_endpoint_without_auth_header_returns_401(self):
        """Prueba que el endpoint /inventory/products retorna 401 sin header de Authorization"""
        response = self.client.get('/inventory/products')
        
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertIn('No autorizado', data['error'])
    
    def test_inventory_products_endpoint_with_invalid_auth_format_returns_401(self):
        """Prueba que el endpoint /inventory/products retorna 401 con formato de header inválido"""
        response = self.client.get('/inventory/products', headers={'Authorization': 'InvalidFormat token123'})
        
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertIn('Formato de token inválido', data['error'])
    
    @patch('app.services.authorizer_service.AuthorizerService.validate_token')
    def test_inventory_products_endpoint_with_invalid_token_returns_401(self, mock_validate_token):
        """Prueba que el endpoint /inventory/products retorna 401 con token inválido"""
        # Configurar mock
        mock_validate_token.return_value = None
        
        # Hacer petición
        response = self.client.get('/inventory/products', headers={'Authorization': 'Bearer invalid_token'})
        
        # Verificar resultado
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertIn('Token inválido', data['error'])
    
    @patch('app.services.authorizer_service.AuthorizerService.validate_token')
    @patch('app.services.authorizer_service.AuthorizerService.get_user_roles')
    @patch('app.services.authorizer_service.AuthorizerService.validate_request')
    def test_inventory_products_endpoint_with_valid_token_but_insufficient_roles_returns_403(self, mock_validate_request, mock_get_roles, mock_validate_token):
        """Prueba que el endpoint /inventory/products retorna 403 con token válido pero sin roles suficientes"""
        # Configurar mocks
        mock_validate_token.return_value = {
            'sub': 'user123',
            'preferred_username': 'testuser',
            'realm_access': {'roles': ['Usuario']}
        }
        mock_get_roles.return_value = ['Usuario']
        mock_validate_request.return_value = (False, "Acceso denegado. Roles requeridos: Administrador, Compras")
        
        # Hacer petición
        response = self.client.get('/inventory/products', headers={'Authorization': 'Bearer valid_token'})
        
        # Verificar resultado
        self.assertEqual(response.status_code, 403)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertIn('Acceso denegado', data['error'])
    
    def test_unknown_endpoint_returns_404(self):
        """Prueba que un endpoint desconocido retorna 404"""
        response = self.client.get('/unknown')
        
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertIn('Endpoint no encontrado', data['error'])
    
    def test_inventory_products_endpoint_supports_all_http_methods(self):
        """Prueba que el endpoint /inventory/products soporta todos los métodos HTTP"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        
        for method in methods:
            with self.subTest(method=method):
                response = self.client.open('/inventory/products', method=method)
                # Debería retornar 401 (sin auth) en lugar de 405 (método no permitido)
                self.assertIn(response.status_code, [401, 404])
    
    def test_inventory_products_endpoint_options_returns_cors_headers(self):
        """Prueba que el endpoint /inventory/products maneja OPTIONS con headers CORS"""
        response = self.client.options('/inventory/products')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), '')
        
        # Verificar headers CORS
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
        self.assertIn('GET, POST, PUT, DELETE, PATCH, OPTIONS', response.headers.get('Access-Control-Allow-Methods'))
        self.assertIn('Content-Type', response.headers.get('Access-Control-Allow-Headers'))
        self.assertIn('Authorization', response.headers.get('Access-Control-Allow-Headers'))
        self.assertEqual(response.headers.get('Access-Control-Max-Age'), '3600')
    
    def test_auth_token_endpoint_options_returns_cors_headers(self):
        """Prueba que el endpoint /auth/token maneja OPTIONS con headers CORS"""
        response = self.client.options('/auth/token')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), '')
        
        # Verificar headers CORS
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
        self.assertIn('GET, POST, PUT, DELETE, PATCH, OPTIONS', response.headers.get('Access-Control-Allow-Methods'))
        self.assertIn('Content-Type', response.headers.get('Access-Control-Allow-Headers'))
        self.assertIn('Authorization', response.headers.get('Access-Control-Allow-Headers'))
        self.assertEqual(response.headers.get('Access-Control-Max-Age'), '3600')
    
    def test_auth_ping_endpoint_options_returns_cors_headers(self):
        """Prueba que el endpoint /auth/ping maneja OPTIONS con headers CORS"""
        response = self.client.options('/auth/ping')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), '')
        
        # Verificar headers CORS
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
        self.assertIn('GET, POST, PUT, DELETE, PATCH, OPTIONS', response.headers.get('Access-Control-Allow-Methods'))
        self.assertIn('Content-Type', response.headers.get('Access-Control-Allow-Headers'))
        self.assertIn('Authorization', response.headers.get('Access-Control-Allow-Headers'))
        self.assertEqual(response.headers.get('Access-Control-Max-Age'), '3600')
    
    def test_unknown_endpoint_options_returns_404(self):
        """Prueba que un endpoint desconocido retorna 404 para OPTIONS"""
        response = self.client.options('/unknown')
        
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertIn('Endpoint no encontrado', data['error'])


if __name__ == '__main__':
    unittest.main()
