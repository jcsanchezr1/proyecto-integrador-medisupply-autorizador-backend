# MediSupply Authorizer Backend

Sistema de autorización backend para el proyecto integrador MediSupply que valida tokens JWT de Keycloak y controla el acceso basado en roles.

## Arquitectura

Sistema de autorización que actúa como proxy/gateway para validar tokens JWT de Keycloak y controlar el acceso basado en roles:

```
├── app/
│   ├── config/                        # Configuración de la aplicación
│   │   └── settings.py                # Configuración de Keycloak, endpoints y roles
│   ├── controllers/                   # Controladores REST
│   │   ├── base_controller.py         # Controlador base
│   │   └── authorizer_controller.py   # Controlador principal del autorizador
│   ├── services/                      # Lógica de negocio
│   │   ├── base_service.py            # Servicio base
│   │   └── authorizer_service.py      # Servicio de autorización y proxy
│   ├── middleware/                    # Middleware de autorización
│   │   └── auth_middleware.py         # Middleware para endpoints públicos
│   ├── exceptions/                    # Manejo de excepciones
│   │   └── custom_exceptions.py       # Excepciones personalizadas
│   └── utils/                         # Utilidades
├── tests/                             # Tests unitarios
├── app.py                            # Punto de entrada de la aplicación
├── requirements.txt                  # Dependencias Python
├── Dockerfile                        # Imagen Docker
├── docker-compose.yml               # Orquestación con Docker Compose
└── README.md                        # Documentación del proyecto
```

### Flujo de Autorización

1. **Middleware** intercepta peticiones y verifica si son endpoints públicos
2. **Controlador** valida tokens JWT con Keycloak
3. **Servicio** extrae roles del usuario y valida permisos
4. **Proxy** redirige peticiones autorizadas a servicios de destino
5. **Respuesta** devuelve resultado del servicio o error de autorización

## Características

- **Autenticación JWT**: Validación de tokens de Keycloak con claves públicas RSA
- **Autorización por Roles**: Control de acceso basado en roles de usuario (realm y cliente)
- **Endpoints Configurables**: Endpoints seguros con roles requeridos definidos en configuración
- **Endpoints Públicos**: Health checks sin autenticación
- **Logging Detallado**: Registro de validaciones, roles y errores para debugging
- **Manejo de Errores**: Códigos de estado HTTP apropiados (401 para autenticación, 403 para autorización)
- **Docker**: Containerización completa para desarrollo y producción
- **CORS**: Habilitado para desarrollo frontend

## Tecnologías

- Python 3.9
- Flask 3.0.3
- PyJWT 2.8.0 (validación JWT)
- Cryptography 42.0.8 (claves RSA)
- Gunicorn 21.2.0
- Docker

## Instalación

### Desarrollo Local

1. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```

2. Ejecutar la aplicación:
   ```bash
   python app.py
   ```

### Pruebas unitarias

1. Correr pruebas unitarias con coverage:
   ```bash
   coverage run -m unittest discover -s tests
   ```

1. Ver reporte de cobertura de las pruebas unitarias
   ```bash
   coverage report
   ```

### Con Docker

1. Construir y ejecutar:
   ```bash
   docker-compose up --build
   ```

2. La aplicación estará disponible en `http://localhost:8081`

## Endpoints

### Endpoints Públicos
- `GET /authorizer/ping` - Health check del autorizador (sin autenticación)

### Endpoints Seguros (Configurables)
Los endpoints seguros se configuran en `app/config/settings.py` bajo `SECURED_ENDPOINTS`:

- `GET/POST/PUT/DELETE /pokemon` - Requiere rol "Administrador"
  - Redirige a: `https://pokeapi.co/api/v2/pokemon`

### Configuración de Endpoints
```python
SECURED_ENDPOINTS = {
    '/pokemon': {
        'target_url': 'https://pokeapi.co/api/v2/pokemon',
        'method': 'ALL',
        'required_roles': ['Administrador']
    }
}
```

### Códigos de Respuesta
- **200**: Petición exitosa
- **401**: Token inválido, expirado o no proporcionado
- **403**: Token válido pero sin permisos suficientes
- **404**: Endpoint no encontrado
- **500**: Error interno del servidor
- **503**: Servicio de destino no disponible
- **504**: Timeout del servicio de destino

## Cloud Run

Para desplegar en Google Cloud Run:

1. Construir imagen:
   ```bash
   docker build -t gcr.io/PROJECT_ID/medisupply-authorizer .
   ```

2. Subir imagen:
   ```bash
   docker push gcr.io/PROJECT_ID/medisupply-authorizer
   ```

3. Desplegar:
   ```bash
   gcloud run deploy medisupply-authorizer \
     --image gcr.io/PROJECT_ID/medisupply-authorizer \
     --platform managed \
     --region us-central1 \
     --allow-unauthenticated \
     --set-env-vars KEYCLOAK_SERVER_URL=https://your-keycloak.com,KEYCLOAK_REALM=medisupply-realm,KEYCLOAK_CLIENT_ID=medisupply-app
   ```

## Logs

La aplicación registra todas las peticiones y validaciones en los logs para facilitar el debugging.
