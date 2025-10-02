# MediSupply Authorizer Backend

Sistema de autorización backend para el proyecto integrador MediSupply que valida tokens JWT de Keycloak y controla el acceso basado en roles.

## Arquitectura

Sistema de autorización con middleware que intercepta todas las peticiones:

```
├── app/
│   ├── config/              # Configuración de Keycloak y roles
│   ├── controllers/         # Controladores REST
│   │   └── authorizer_controller.py  # Todos los endpoints del autorizador
│   ├── services/            # Lógica de negocio
│   │   └── auth_service.py           # Servicio de autenticación Keycloak
│   ├── middleware/          # Middleware de autorización
│   │   └── auth_middleware.py        # Interceptor de peticiones
│   ├── repositories/        # Acceso a datos (estructura)
│   ├── models/              # Modelos de datos (estructura)
│   ├── exceptions/          # Excepciones (estructura)
│   └── utils/               # Utilidades (estructura)
├── tests/                   # Tests (estructura)
├── app.py                  # Punto de entrada
├── requirements.txt        # Dependencias incluyendo PyJWT
├── Dockerfile             # Containerización
├── docker-compose.yml     # Orquestación
└── README.md              # Documentación
```

## Características

- **Autenticación JWT**: Validación de tokens de Keycloak
- **Autorización por Roles**: Control de acceso basado en roles de usuario
- **Middleware Global**: Intercepta todas las peticiones automáticamente
- **Endpoints Públicos**: Health checks sin autenticación
- **Logging**: Registro detallado de peticiones y validaciones
- **Docker**: Containerización para local y Cloud Run
- **CORS**: Habilitado para desarrollo

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

### Con Docker

1. Construir y ejecutar:
   ```bash
   docker-compose up --build
   ```

2. La aplicación estará disponible en `http://localhost:8081`

## Endpoints

### Health Check
- `GET /authorizer/ping` - Ping simple

## Respuesta del Health Check

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "service": "MediSupply Authorizer Backend",
  "version": "1.0.0",
  "environment": "development"
}
```

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
