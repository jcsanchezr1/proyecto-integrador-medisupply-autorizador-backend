"""
Pruebas unitarias para el controlador de autorización usando unittest
"""
import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Agregar el directorio padre al path para importar la app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.controllers.authorizer_controller import AuthorizerView


class TestAuthorizerController(unittest.TestCase):
    """Pruebas para AuthorizerView usando unittest"""
    
    def setUp(self):
        """Configuración antes de cada prueba"""
        # Crear una aplicación Flask para el contexto
        from app import create_app
        self.app = create_app()
        self.app.config['TESTING'] = True
        
        with self.app.app_context():
            self.controller = AuthorizerView()
    
    def test_controller_initialization(self):
        """Prueba que el controlador se inicializa correctamente"""
        self.assertIsNotNone(self.controller)
        self.assertIsNotNone(self.controller.authorizer_service)
    
    def test_controller_has_required_methods(self):
        """Prueba que el controlador tiene todos los métodos HTTP requeridos"""
        required_methods = ['get', 'post', 'put', 'delete', 'patch', 'options']
        
        for method in required_methods:
            self.assertTrue(hasattr(self.controller, method))
            self.assertTrue(callable(getattr(self.controller, method)))
    
    def test_get_method_calls_handle_request(self):
        """Prueba que el método get llama a _handle_request"""
        with patch.object(self.controller, '_handle_request') as mock_handle:
            mock_handle.return_value = ({'data': 'test'}, 200)
            
            result = self.controller.get()
            
            mock_handle.assert_called_once_with(None)
            self.assertEqual(result, ({'data': 'test'}, 200))
    
    def test_post_method_calls_handle_request(self):
        """Prueba que el método post llama a _handle_request"""
        with patch.object(self.controller, '_handle_request') as mock_handle:
            mock_handle.return_value = ({'data': 'test'}, 200)
            
            result = self.controller.post()
            
            mock_handle.assert_called_once_with(None)
            self.assertEqual(result, ({'data': 'test'}, 200))
    
    def test_put_method_calls_handle_request(self):
        """Prueba que el método put llama a _handle_request"""
        with patch.object(self.controller, '_handle_request') as mock_handle:
            mock_handle.return_value = ({'data': 'test'}, 200)
            
            result = self.controller.put()
            
            mock_handle.assert_called_once_with(None)
            self.assertEqual(result, ({'data': 'test'}, 200))
    
    def test_delete_method_calls_handle_request(self):
        """Prueba que el método delete llama a _handle_request"""
        with patch.object(self.controller, '_handle_request') as mock_handle:
            mock_handle.return_value = ({'data': 'test'}, 200)
            
            result = self.controller.delete()
            
            mock_handle.assert_called_once_with(None)
            self.assertEqual(result, ({'data': 'test'}, 200))
    
    def test_patch_method_calls_handle_request(self):
        """Prueba que el método patch llama a _handle_request"""
        with patch.object(self.controller, '_handle_request') as mock_handle:
            mock_handle.return_value = ({'data': 'test'}, 200)
            
            result = self.controller.patch()
            
            mock_handle.assert_called_once_with(None)
            self.assertEqual(result, ({'data': 'test'}, 200))
    
    def test_options_method_calls_handle_request(self):
        """Prueba que el método options llama a _handle_request"""
        with patch.object(self.controller, '_handle_request') as mock_handle:
            mock_handle.return_value = ({'data': 'test'}, 200)
            
            result = self.controller.options()
            
            mock_handle.assert_called_once_with(None)
            self.assertEqual(result, ({'data': 'test'}, 200))
    
    def test_handle_options_request_secured_endpoint(self):
        """Prueba que _handle_options_request maneja endpoints seguros correctamente"""
        with self.app.test_request_context('/pokemon'):
            with patch('flask.current_app') as mock_app:
                mock_app.config = Mock()
                mock_app.config.get.side_effect = lambda key, default=None: {
                    'SECURED_ENDPOINTS': {
                        '/pokemon': {'target_url': 'http://example.com', 'method': 'ALL'},
                        '/auth/admin/users': {'target_url': 'http://example.com', 'method': 'POST'}
                    },
                    'PUBLIC_EXTERNAL_ENDPOINTS': {}
                }.get(key, default)
                
                result = self.controller._handle_options_request('/pokemon')
                
                # Debería retornar una respuesta con headers CORS
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.get_data(as_text=True), '')  # empty body
                self.assertEqual(result.headers.get('Access-Control-Allow-Origin'), '*')
    
    def test_handle_options_request_public_endpoint(self):
        """Prueba que _handle_options_request maneja endpoints públicos correctamente"""
        with self.app.test_request_context('/auth/token'):
            with patch('flask.current_app') as mock_app:
                mock_app.config = Mock()
                mock_app.config.get.side_effect = lambda key, default=None: {
                    'SECURED_ENDPOINTS': {},
                    'PUBLIC_EXTERNAL_ENDPOINTS': {
                        '/auth/token': {'target_url': 'http://example.com', 'method': 'POST'}
                    }
                }.get(key, default)
                
                result = self.controller._handle_options_request('/auth/token')
                
                # Debería retornar una respuesta con headers CORS
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.get_data(as_text=True), '')  # empty body
                self.assertEqual(result.headers.get('Access-Control-Allow-Origin'), '*')
    
    def test_handle_options_request_unknown_endpoint(self):
        """Prueba que _handle_options_request retorna 404 para endpoints desconocidos"""
        with self.app.test_request_context('/unknown'):
            with patch('flask.current_app') as mock_app:
                mock_app.config = Mock()
                mock_app.config.get.return_value = {}
                
                result = self.controller._handle_options_request('/unknown')
                
                # Debería retornar 404
                self.assertEqual(result[1], 404)
                self.assertIn('error', result[0])
                self.assertIn('Endpoint no encontrado', result[0]['error'])
    
    def test_handle_options_request_cors_headers(self):
        """Prueba que _handle_options_request incluye todos los headers CORS necesarios"""
        with self.app.test_request_context('/pokemon'):
            with patch('flask.current_app') as mock_app:
                mock_app.config = Mock()
                mock_app.config.get.side_effect = lambda key, default=None: {
                    'SECURED_ENDPOINTS': {
                        '/pokemon': {'target_url': 'http://example.com', 'method': 'ALL'}
                    },
                    'PUBLIC_EXTERNAL_ENDPOINTS': {}
                }.get(key, default)
                
                result = self.controller._handle_options_request('/pokemon')
                
                # Verificar headers CORS
                self.assertEqual(result.headers.get('Access-Control-Allow-Origin'), '*')
                self.assertIn('GET, POST, PUT, DELETE, PATCH, OPTIONS', 
                             result.headers.get('Access-Control-Allow-Methods'))
                self.assertIn('Content-Type', result.headers.get('Access-Control-Allow-Headers'))
                self.assertIn('Authorization', result.headers.get('Access-Control-Allow-Headers'))
                self.assertEqual(result.headers.get('Access-Control-Max-Age'), '3600')
    
    def test_handle_options_request_with_custom_headers(self):
        """Prueba que _handle_options_request maneja headers personalizados en la petición"""
        with self.app.test_request_context('/pokemon', headers={'Access-Control-Request-Headers': 'Content-Type, Authorization, X-Custom-Header'}):
            with patch('flask.current_app') as mock_app:
                mock_app.config = Mock()
                mock_app.config.get.side_effect = lambda key, default=None: {
                    'SECURED_ENDPOINTS': {
                        '/pokemon': {'target_url': 'http://example.com', 'method': 'ALL'}
                    },
                    'PUBLIC_EXTERNAL_ENDPOINTS': {}
                }.get(key, default)
                
                result = self.controller._handle_options_request('/pokemon')
                
                # Verificar que los headers personalizados se incluyen
                allowed_headers = result.headers.get('Access-Control-Allow-Headers')
                self.assertIn('Content-Type', allowed_headers)
                self.assertIn('Authorization', allowed_headers)
                self.assertIn('X-Custom-Header', allowed_headers)


if __name__ == '__main__':
    unittest.main()
