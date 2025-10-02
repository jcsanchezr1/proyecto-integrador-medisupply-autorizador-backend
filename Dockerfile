FROM python:3.9-slim

# Establecer directorio de trabajo
WORKDIR /app

# Copiar archivos de dependencias
COPY requirements.txt /app/

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código de la aplicación
COPY . /app

# Exponer puerto
EXPOSE 8080

# Variables de entorno
ENV FLASK_APP=app.py

# Comando por defecto
CMD ["python", "app.py"]