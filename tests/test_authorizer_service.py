"""
Pruebas unitarias para el servicio de autorización usando unittest
"""
import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Agregar el directorio padre al path para importar la app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.services.authorizer_service import AuthorizerService


class TestAuthorizerService(unittest.TestCase):
    """Pruebas para AuthorizerService usando unittest"""
    
    def setUp(self):
        """Configuración antes de cada prueba"""
        # Crear una aplicación Flask para el contexto
        from app import create_app
        self.app = create_app()
        self.app.config['TESTING'] = True
        
        with self.app.app_context():
            self.service = AuthorizerService()
    
    def test_has_required_role_with_valid_role(self):
        """Prueba que has_required_role retorna True cuando el usuario tiene el rol requerido"""
        user_roles = ['Administrador', 'Usuario']
        required_roles = ['Administrador']
        
        result = self.service.has_required_role(user_roles, required_roles)
        
        self.assertTrue(result)
    
    def test_has_required_role_without_valid_role(self):
        """Prueba que has_required_role retorna False cuando el usuario no tiene el rol requerido"""
        user_roles = ['Usuario', 'Editor']
        required_roles = ['Administrador']
        
        result = self.service.has_required_role(user_roles, required_roles)
        
        self.assertFalse(result)
    
    def test_has_required_role_with_multiple_required_roles(self):
        """Prueba que has_required_role retorna True cuando el usuario tiene al menos uno de los roles requeridos"""
        user_roles = ['Usuario', 'Editor']
        required_roles = ['Administrador', 'Editor']
        
        result = self.service.has_required_role(user_roles, required_roles)
        
        self.assertTrue(result)
    
    def test_validate_request_with_valid_roles(self):
        """Prueba que validate_request retorna True cuando el usuario tiene los roles requeridos"""
        endpoint_config = {'required_roles': ['Administrador']}
        user_roles = ['Administrador', 'Usuario']
        
        is_valid, error_message = self.service.validate_request(endpoint_config, user_roles)
        
        self.assertTrue(is_valid)
        self.assertEqual(error_message, "")
    
    def test_validate_request_without_valid_roles(self):
        """Prueba que validate_request retorna False cuando el usuario no tiene los roles requeridos"""
        endpoint_config = {'required_roles': ['Administrador']}
        user_roles = ['Usuario', 'Editor']
        
        is_valid, error_message = self.service.validate_request(endpoint_config, user_roles)
        
        self.assertFalse(is_valid)
        self.assertIn("Acceso denegado", error_message)
        self.assertIn("Administrador", error_message)
    
    def test_validate_request_without_required_roles(self):
        """Prueba que validate_request retorna True cuando no hay roles requeridos"""
        endpoint_config = {}
        user_roles = ['Usuario']
        
        is_valid, error_message = self.service.validate_request(endpoint_config, user_roles)
        
        self.assertTrue(is_valid)
        self.assertEqual(error_message, "")
    
    def test_get_user_roles_from_realm_access(self):
        """Prueba que get_user_roles extrae roles del realm_access"""
        token_payload = {
            'realm_access': {
                'roles': ['default-roles-medisupply-realm', 'offline_access', 'uma_authorization']
            }
        }
        
        roles = self.service.get_user_roles(token_payload)
        
        self.assertIn('default-roles-medisupply-realm', roles)
        self.assertIn('offline_access', roles)
        self.assertIn('uma_authorization', roles)
    
    def test_get_user_roles_from_resource_access(self):
        """Prueba que get_user_roles extrae roles del resource_access"""
        token_payload = {
            'resource_access': {
                'medisupply-client': {
                    'roles': ['Administrador', 'Usuario']
                }
            }
        }
        
        roles = self.service.get_user_roles(token_payload)
        
        self.assertIn('Administrador', roles)
        self.assertIn('Usuario', roles)
    
    def test_get_user_roles_from_both_sources(self):
        """Prueba que get_user_roles extrae roles de ambos realm_access y resource_access"""
        token_payload = {
            'realm_access': {
                'roles': ['default-roles-medisupply-realm']
            },
            'resource_access': {
                'medisupply-client': {
                    'roles': ['Administrador']
                }
            }
        }
        
        roles = self.service.get_user_roles(token_payload)
        
        self.assertIn('default-roles-medisupply-realm', roles)
        self.assertIn('Administrador', roles)
        self.assertEqual(len(roles), 2)
    
    def test_get_user_roles_with_empty_payload(self):
        """Prueba que get_user_roles retorna lista vacía con payload vacío"""
        token_payload = {}
        
        roles = self.service.get_user_roles(token_payload)
        
        self.assertEqual(roles, [])
    
    def test_get_user_info(self):
        """Prueba que get_user_info extrae información correcta del usuario"""
        token_payload = {
            'sub': 'user-123',
            'preferred_username': 'testuser',
            'email': 'test@example.com',
            'name': 'Test User',
            'realm_access': {
                'roles': ['Administrador']
            }
        }
        
        user_info = self.service.get_user_info(token_payload)
        
        self.assertEqual(user_info['user_id'], 'user-123')
        self.assertEqual(user_info['username'], 'testuser')
        self.assertEqual(user_info['email'], 'test@example.com')
        self.assertEqual(user_info['name'], 'Test User')
        self.assertIn('Administrador', user_info['roles'])
    
    def test_is_authorizer_endpoint_with_valid_endpoint(self):
        """Prueba que is_authorizer_endpoint retorna True para endpoints configurados"""
        with self.app.app_context():
            result = self.service.is_authorizer_endpoint('/pokemon')
            self.assertTrue(result)
    
    def test_is_authorizer_endpoint_with_invalid_endpoint(self):
        """Prueba que is_authorizer_endpoint retorna False para endpoints no configurados"""
        with self.app.app_context():
            result = self.service.is_authorizer_endpoint('/unknown')
            self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
