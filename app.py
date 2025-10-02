"""
Punto de entrada principal de la aplicación
"""
import os
from app import create_app

# Crear la aplicación
app = create_app()

if __name__ == '__main__':
    # Configuración para desarrollo local
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 8080))
    debug = os.getenv('DEBUG', 'True').lower() == 'true'
    
    print(f"Starting MediSupply Authorizer Backend on {host}:{port}")
    print(f"Debug mode: {debug}")
    
    app.run(host=host, port=port, debug=debug)