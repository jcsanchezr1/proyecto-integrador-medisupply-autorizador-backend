"""
Configuración de la aplicación - Estructura para manejar configuraciones
"""
import os


class Config:
    """Configuración base de la aplicación"""
    
    # Configuración básica
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', '8080'))
    
    # Configuración de la aplicación
    APP_NAME = 'MediSupply Authorizer Backend'
    APP_VERSION = '1.0.0'
    
    # Configuración de Keycloak
    KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080')
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'medisupply-realm')
    KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'medisupply-client')
    
    # Configuración de JWT
    JWT_ALGORITHM = 'RS256'
    JWT_ISSUER = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}"
    
    # Endpoints que no requieren autenticación
    PUBLIC_ENDPOINTS = ['/authorizer/ping']
    
    # Variables de entorno para URLs de servicios
    AUTHENTICATOR_SERVICE_URL = os.getenv('AUTHENTICATOR_SERVICE_URL', 'https://medisupply-authenticator-ms-1034901101791.us-central1.run.app')
    INVENTORIES_SERVICE_URL = os.getenv('INVENTORIES_SERVICE_URL', 'https://medisupply-inventory-ms-1034901101791.us-central1.run.app')
    PROVIDERS_SERVICE_URL = os.getenv('PROVIDERS_SERVICE_URL', 'https://medisupply-provider-ms-1034901101791.us-central1.run.app')
    ORDERS_SERVICE_URL = os.getenv('ORDERS_SERVICE_URL', 'https://medisupply-order-ms-1034901101791.us-central1.run.app')
    SALES_PLAN_SERVICE_URL = os.getenv('SALES_PLAN_SERVICE_URL', 'https://medisupply-sales-plan-ms-1034901101791.us-central1.run.app')
    LOGISTICS_SERVICE_URL = os.getenv('LOGISTICS_SERVICE_URL', 'https://medisupply-logistics-ms-1034901101791.us-central1.run.app')
    
    # Configuración de endpoints seguros (Autorizador)
    SECURED_ENDPOINTS = {
        '/auth/admin/users': {
            'target_url': f"{AUTHENTICATOR_SERVICE_URL}/auth/admin/users",
            'method': 'POST',
            'required_roles': ['Administrador']
        },
        '/auth/user': {
            'target_url': f"{AUTHENTICATOR_SERVICE_URL}/auth/user",
            'method': 'GET',
            'required_roles': ['Administrador']
        },
        '/auth/user/all': {
            'target_url': f"{AUTHENTICATOR_SERVICE_URL}/auth/user/all",
            'method': 'DELETE',
            'required_roles': ['Administrador']
        },
        '/inventory/products': {
            'target_url': f"{INVENTORIES_SERVICE_URL}/inventory/products",
            'method': 'ALL',
            'required_roles': ['Administrador', 'Compras', 'Logistica']
        },
        '/inventory/providers/products': {
            'target_url': f"{INVENTORIES_SERVICE_URL}/inventory/providers/products",
            'method': 'GET',
            'required_roles': ['Administrador', 'Ventas', 'Cliente']
        },
        '/providers': {
            'target_url': f"{PROVIDERS_SERVICE_URL}/providers",
            'method': 'ALL',
            'required_roles': ['Administrador', 'Compras']
        },
        '/providers/all': {
            'target_url': f"{PROVIDERS_SERVICE_URL}/providers/all",
            'method': 'DELETE',
            'required_roles': ['Administrador', 'Compras']
        },
        '/orders/reports/monthly': {
            'target_url': f"{ORDERS_SERVICE_URL}/orders/reports/monthly",
            'method': 'GET',
            'required_roles': ['Administrador', 'Ventas']
        },
        '/orders/reports/top-clients': {
            'target_url': f"{ORDERS_SERVICE_URL}/orders/reports/top-clients",
            'method': 'GET',
            'required_roles': ['Administrador', 'Ventas']
        },
        '/orders/reports/top-products': {
            'target_url': f"{ORDERS_SERVICE_URL}/orders/reports/top-products",
            'method': 'GET',
            'required_roles': ['Administrador', 'Ventas']
        },
        '/orders/create': {
            'target_url': f"{ORDERS_SERVICE_URL}/orders/create",
            'method': 'POST',
            'required_roles': ['Administrador', 'Ventas', 'Cliente']
        },
        '/orders/delete-all': {
            'target_url': f"{ORDERS_SERVICE_URL}/orders/delete-all",
            'method': 'DELETE',
            'required_roles': ['Administrador', 'Ventas', 'Cliente']
        },
        '/orders': {
            'target_url': f"{ORDERS_SERVICE_URL}/orders",
            'method': 'GET',
            'required_roles': ['Administrador', 'Ventas', 'Cliente']
        },
        '/auth/assigned-clients': {
            'target_url': f"{AUTHENTICATOR_SERVICE_URL}/auth/assigned-clients",
            'method': 'ALL',
            'required_roles': ['Administrador', 'Ventas']
        },
        '/sales-plan': {
            'target_url': f"{SALES_PLAN_SERVICE_URL}/sales-plan",
            'method': 'GET',
            'required_roles': ['Administrador', 'Ventas']
        },
        '/sales-plan/create': {
            'target_url': f"{SALES_PLAN_SERVICE_URL}/sales-plan/create",
            'method': 'POST',
            'required_roles': ['Administrador', 'Ventas']
        },
        '/sales-plan/delete-all': {
            'target_url': f"{SALES_PLAN_SERVICE_URL}/sales-plan/delete-all",
            'method': 'DELETE',
            'required_roles': ['Administrador', 'Ventas']
        },
        '/logistics/routes': {
            'target_url': f"{LOGISTICS_SERVICE_URL}/logistics/routes",
            'method': 'ALL',
            'required_roles': ['Administrador', 'Logistica']
        },
        '/sellers': {
            'target_url': f"{SALES_PLAN_SERVICE_URL}/sellers",
            'method': 'ALL',
            'required_roles': ['Administrador', 'Ventas']
        }
    }
    
    # Configuración de endpoints públicos externos (sin autenticación)
    PUBLIC_EXTERNAL_ENDPOINTS = {
        '/auth/ping': {
            'target_url': f"{AUTHENTICATOR_SERVICE_URL}/auth/ping",
            'method': 'GET'
        },
        '/auth/user': {
            'target_url': f"{AUTHENTICATOR_SERVICE_URL}/auth/user",
            'method': 'POST'
        },
        '/auth/user/get': {
            'target_url': f"{AUTHENTICATOR_SERVICE_URL}/auth/user",
            'method': 'GET'
        },
        '/auth/token': {
            'target_url': f"{AUTHENTICATOR_SERVICE_URL}/auth/token",
            'method': 'POST'
        },
        '/auth/logout': {
            'target_url': f"{AUTHENTICATOR_SERVICE_URL}/auth/logout",
            'method': 'POST'
        },
        '/inventory/ping': {
            'target_url': f"{INVENTORIES_SERVICE_URL}/inventory/ping",
            'method': 'GET'
        },
        '/providers/ping': {
            'target_url': f"{PROVIDERS_SERVICE_URL}/providers/ping",
            'method': 'GET'
        },
        '/orders/ping': {
            'target_url': f"{ORDERS_SERVICE_URL}/orders/ping",
            'method': 'GET'
        },
        '/sales-plan/ping': {
            'target_url': f"{SALES_PLAN_SERVICE_URL}/sales-plan/ping",
            'method': 'GET'
        },
        '/logistics/ping': {
            'target_url': f"{LOGISTICS_SERVICE_URL}/logistics/ping",
            'method': 'GET'
        }
    }


class DevelopmentConfig(Config):
    """Configuración para desarrollo"""
    DEBUG = True


class ProductionConfig(Config):
    """Configuración para producción"""
    DEBUG = False


def get_config():
    """Retorna la configuración según el entorno"""
    env = os.getenv('FLASK_ENV', 'development').lower()
    
    if env == 'production':
        return ProductionConfig()
    else:
        return DevelopmentConfig()