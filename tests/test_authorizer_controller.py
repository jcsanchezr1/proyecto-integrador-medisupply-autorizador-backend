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
    
    @patch('app.controllers.authorizer_controller.request')
    @patch('app.controllers.authorizer_controller.current_app')
    def test_handle_request_without_auth_header_returns_401(self, mock_app, mock_request):
        """Prueba que _handle_request retorna 401 cuando no hay header de Authorization"""
        # Configurar mocks
        mock_request.path = '/pokemon'
        mock_request.headers = {}
        mock_app.config = {
            'SECURED_ENDPOINTS': {
                '/pokemon': {
                    'target_url': 'http://example.com',
                    'required_roles': ['Administrador']
                }
            }
        }
        
        # Ejecutar método
        result, status_code = self.controller._handle_request()
        
        # Verificar resultado
        self.assertEqual(status_code, 401)
        self.assertIn('error', result)
        self.assertIn('No autorizado', result['error'])
    
    @patch('app.controllers.authorizer_controller.request')
    @patch('app.controllers.authorizer_controller.current_app')
    def test_handle_request_with_invalid_auth_format_returns_401(self, mock_app, mock_request):
        """Prueba que _handle_request retorna 401 cuando el formato del header es inválido"""
        # Configurar mocks
        mock_request.path = '/pokemon'
        mock_request.headers = {'Authorization': 'InvalidFormat token123'}
        mock_app.config = {
            'SECURED_ENDPOINTS': {
                '/pokemon': {
                    'target_url': 'http://example.com',
                    'required_roles': ['Administrador']
                }
            }
        }
        
        # Ejecutar método
        result, status_code = self.controller._handle_request()
        
        # Verificar resultado
        self.assertEqual(status_code, 401)
        self.assertIn('error', result)
        self.assertIn('Formato de token inválido', result['error'])
    
    @patch('app.controllers.authorizer_controller.request')
    @patch('app.controllers.authorizer_controller.current_app')
    @patch('app.controllers.authorizer_controller.AuthorizerService')
    def test_handle_request_with_invalid_token_returns_401(self, mock_service_class, mock_app, mock_request):
        """Prueba que _handle_request retorna 401 cuando el token es inválido"""
        # Configurar mocks
        mock_request.path = '/pokemon'
        mock_request.headers = {'Authorization': 'Bearer invalid_token'}
        mock_app.config = {
            'SECURED_ENDPOINTS': {
                '/pokemon': {
                    'target_url': 'http://example.com',
                    'required_roles': ['Administrador']
                }
            }
        }
        
        # Mock del servicio
        mock_service = Mock()
        mock_service.validate_token.return_value = None  # Token inválido
        mock_service_class.return_value = mock_service
        
        # Ejecutar método
        result, status_code = self.controller._handle_request()
        
        # Verificar resultado
        self.assertEqual(status_code, 401)
        self.assertIn('error', result)
        self.assertIn('Token inválido', result['error'])
    
    @patch('app.controllers.authorizer_controller.request')
    @patch('app.controllers.authorizer_controller.current_app')
    @patch('app.controllers.authorizer_controller.AuthorizerService')
    def test_handle_request_with_valid_token_but_insufficient_roles_returns_403(self, mock_service_class, mock_app, mock_request):
        """Prueba que _handle_request retorna 403 cuando el token es válido pero no tiene roles suficientes"""
        # Configurar mocks
        mock_request.path = '/pokemon'
        mock_request.headers = {'Authorization': 'Bearer valid_token'}
        mock_app.config = {
            'SECURED_ENDPOINTS': {
                '/pokemon': {
                    'target_url': 'http://example.com',
                    'required_roles': ['Administrador']
                }
            }
        }
        
        # Mock del servicio
        mock_service = Mock()
        mock_service.validate_token.return_value = {'sub': 'user123', 'preferred_username': 'testuser'}
        mock_service.get_user_roles.return_value = ['Usuario']  # Sin rol Administrador
        mock_service.validate_request.return_value = (False, "Acceso denegado. Roles requeridos: Administrador")
        mock_service_class.return_value = mock_service
        
        # Ejecutar método
        result, status_code = self.controller._handle_request()
        
        # Verificar resultado
        self.assertEqual(status_code, 403)
        self.assertIn('error', result)
        self.assertIn('Acceso denegado', result['error'])
    
    @patch('app.controllers.authorizer_controller.request')
    @patch('app.controllers.authorizer_controller.current_app')
    def test_handle_request_with_unknown_endpoint_returns_404(self, mock_app, mock_request):
        """Prueba que _handle_request retorna 404 cuando el endpoint no está configurado"""
        # Configurar mocks
        mock_request.path = '/unknown'
        mock_app.config = {
            'SECURED_ENDPOINTS': {
                '/pokemon': {
                    'target_url': 'http://example.com',
                    'required_roles': ['Administrador']
                }
            }
        }
        
        # Ejecutar método
        result, status_code = self.controller._handle_request()
        
        # Verificar resultado
        self.assertEqual(status_code, 404)
        self.assertIn('error', result)
        self.assertIn('Endpoint no encontrado', result['error'])
    
    @patch('app.controllers.authorizer_controller.request')
    @patch('app.controllers.authorizer_controller.current_app')
    def test_handle_request_with_public_endpoint_no_auth_required(self, mock_app, mock_request):
        """Prueba que _handle_request no requiere autenticación para endpoints públicos"""
        # Configurar mocks
        mock_request.path = '/authorizer/ping'
        mock_app.config = {
            'SECURED_ENDPOINTS': {},
            'PUBLIC_ENDPOINTS': ['/authorizer/ping']
        }
        
        # Mock del servicio para forward_request
        with patch.object(self.controller.authorizer_service, 'forward_request') as mock_forward:
            mock_forward.return_value = ({'data': 'pong'}, 200)
            
            # Ejecutar método
            result, status_code = self.controller._handle_request()
            
            # Verificar resultado
            self.assertEqual(status_code, 200)
            self.assertIn('data', result)
    
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
