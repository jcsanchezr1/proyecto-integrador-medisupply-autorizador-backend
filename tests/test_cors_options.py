"""
Pruebas específicas para CORS y manejo de OPTIONS
"""
import unittest
import sys
import os
from unittest.mock import patch, Mock

# Agregar el directorio padre al path para importar la app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import create_app


class TestCorsOptions(unittest.TestCase):
    """Pruebas específicas para CORS y manejo de OPTIONS"""
    
    def setUp(self):
        """Configuración antes de cada prueba"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
    
    def test_cors_headers_present_in_all_responses(self):
        """Prueba que los headers CORS están presentes en todas las respuestas"""
        endpoints = ['/authorizer/ping', '/pokemon', '/auth/token', '/auth/ping']
        
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                # Verificar que el header Access-Control-Allow-Origin está presente
                self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
    
    def test_options_secured_endpoints_return_200_with_cors(self):
        """Prueba que OPTIONS en endpoints seguros retorna 200 con headers CORS"""
        secured_endpoints = ['/pokemon', '/auth/admin/users', '/auth/user', '/auth/user/all']
        
        for endpoint in secured_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.options(endpoint)
                
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_data(as_text=True), '')
                
                # Verificar headers CORS
                self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
                self.assertIn('GET, POST, PUT, DELETE, PATCH, OPTIONS', 
                             response.headers.get('Access-Control-Allow-Methods'))
                self.assertIn('Content-Type', response.headers.get('Access-Control-Allow-Headers'))
                self.assertIn('Authorization', response.headers.get('Access-Control-Allow-Headers'))
                self.assertEqual(response.headers.get('Access-Control-Max-Age'), '3600')
    
    def test_options_public_external_endpoints_return_200_with_cors(self):
        """Prueba que OPTIONS en endpoints públicos externos retorna 200 con headers CORS"""
        public_endpoints = ['/auth/ping', '/auth/user', '/auth/token', '/auth/logout']
        
        for endpoint in public_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.options(endpoint)
                
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_data(as_text=True), '')
                
                # Verificar headers CORS
                self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
                self.assertIn('GET, POST, PUT, DELETE, PATCH, OPTIONS', 
                             response.headers.get('Access-Control-Allow-Methods'))
                self.assertIn('Content-Type', response.headers.get('Access-Control-Allow-Headers'))
                self.assertIn('Authorization', response.headers.get('Access-Control-Allow-Headers'))
                self.assertEqual(response.headers.get('Access-Control-Max-Age'), '3600')
    
    def test_options_with_custom_headers_in_request(self):
        """Prueba que OPTIONS maneja headers personalizados en la petición"""
        response = self.client.options('/auth/token', headers={
            'Access-Control-Request-Headers': 'Content-Type, Authorization, X-Custom-Header'
        })
        
        self.assertEqual(response.status_code, 200)
        
        # Verificar que los headers personalizados se incluyen en la respuesta
        allowed_headers = response.headers.get('Access-Control-Allow-Headers')
        self.assertIn('Content-Type', allowed_headers)
        self.assertIn('Authorization', allowed_headers)
        self.assertIn('X-Custom-Header', allowed_headers)
    
    def test_options_unknown_endpoint_returns_404(self):
        """Prueba que OPTIONS en endpoint desconocido retorna 404"""
        response = self.client.options('/unknown/endpoint')
        
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertIn('Endpoint no encontrado', data['error'])
    
    def test_cors_preflight_workflow(self):
        """Prueba el flujo completo de CORS preflight"""
        # Simular petición preflight típica
        response = self.client.options('/auth/token', headers={
            'Origin': 'https://example.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type, Authorization'
        })
        
        self.assertEqual(response.status_code, 200)
        
        # Verificar headers de respuesta CORS
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
        self.assertIn('POST', response.headers.get('Access-Control-Allow-Methods'))
        self.assertIn('Content-Type', response.headers.get('Access-Control-Allow-Headers'))
        self.assertIn('Authorization', response.headers.get('Access-Control-Allow-Headers'))
        self.assertEqual(response.headers.get('Access-Control-Max-Age'), '3600')
    
    def test_all_configured_endpoints_support_options(self):
        """Prueba que todos los endpoints configurados soportan OPTIONS"""
        from app.config.settings import get_config
        config = get_config()
        
        # Obtener todos los endpoints configurados
        all_endpoints = []
        all_endpoints.extend(config.SECURED_ENDPOINTS.keys())
        all_endpoints.extend(config.PUBLIC_EXTERNAL_ENDPOINTS.keys())
        
        for endpoint in all_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.options(endpoint)
                
                # Todos los endpoints configurados deben retornar 200 para OPTIONS
                self.assertEqual(response.status_code, 200)
                
                # Verificar headers CORS básicos
                self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')
                self.assertIsNotNone(response.headers.get('Access-Control-Allow-Methods'))
                self.assertIsNotNone(response.headers.get('Access-Control-Allow-Headers'))
    
    def test_options_response_has_correct_content_type(self):
        """Prueba que la respuesta OPTIONS tiene el content-type correcto"""
        response = self.client.options('/auth/token')
        
        self.assertEqual(response.status_code, 200)
        # El content-type debe ser text/html para respuestas OPTIONS vacías
        self.assertIn('text/html', response.headers.get('Content-Type'))
    
    def test_options_response_is_empty(self):
        """Prueba que la respuesta OPTIONS está vacía"""
        response = self.client.options('/auth/token')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), '')
        self.assertEqual(len(response.get_data()), 0)


if __name__ == '__main__':
    unittest.main()
