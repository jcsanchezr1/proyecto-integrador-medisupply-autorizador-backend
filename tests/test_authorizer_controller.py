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


if __name__ == '__main__':
    unittest.main()
