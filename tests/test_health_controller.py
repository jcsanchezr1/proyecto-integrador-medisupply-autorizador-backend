"""
Pruebas unitarias para el controlador de health check usando unittest
"""
import unittest
import sys
import os

# Agregar el directorio padre al path para importar la app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.controllers.health_controller import HealthCheckView


class TestHealthController(unittest.TestCase):
    """Pruebas para HealthCheckView usando unittest"""
    
    def test_health_check_returns_pong(self):
        """Prueba que el health check retorna 'pong'"""
        controller = HealthCheckView()
        result, status_code = controller.get()
        
        self.assertEqual(result, "pong")
        self.assertEqual(status_code, 200)
    
    def test_health_check_is_get_method(self):
        """Prueba que el health check responde al método GET"""
        controller = HealthCheckView()
        
        # Verificar que tiene el método get
        self.assertTrue(hasattr(controller, 'get'))
        self.assertTrue(callable(getattr(controller, 'get')))


if __name__ == '__main__':
    unittest.main()
