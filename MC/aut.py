# crear_usuario_temporal.py

import os
import django

# Carga la configuración de Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MC.settings')
django.setup()

from Miapp.models import UserAuth

# --- Parámetros del nuevo usuario ---
email = 'Tester@gmail.com'
password = 'TestLogin'
nombre = 'Tester'
# -----------------------------------

try:
    # 1. Asegura que no haya un usuario viejo sin cifrar
    UserAuth.objects.filter(email=email).delete() 
    
    # 2. Crea el usuario usando el método que garantiza el hashing
    # Tu método create_user() llama a user.set_password(password)
    user = UserAuth.objects.create_user(
        nombre=nombre, 
        email=email, 
        password=password
    )
    print(f"✅ Usuario {nombre} creado con contraseña cifrada automáticamente.")

except Exception as e:
    print(f"❌ Error al crear el usuario: {e}")