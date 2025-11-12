import json
import datetime
import os
import re
from django.core.exceptions import ValidationError
from django.db import transaction, models
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from cryptography.fernet import Fernet

def get_fernet():
    return Fernet(settings.FERNET_KEY.encode())

class UserAuthManager(BaseUserManager):
    def create_user(self, nombre, email, password=None, **extra_fields):
        if not nombre:
            raise ValueError('El campo "nombre" es obligatorio.')
        if not email:
            raise ValueError('El campo "email" es obligatorio.')
        email = self.normalize_email(email)
        user = self.model(nombre=nombre, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, nombre, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('El superusuario debe tener is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('El superusuario debe tener is_superuser=True.')
        return self.create_user(nombre, email, password, **extra_fields)

class UserAuth(AbstractBaseUser, PermissionsMixin):
    nombre = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['nombre']
    objects = UserAuthManager()

    def __str__(self):
        return self.nombre

class Usuario(models.Model):
    id_usuario = models.AutoField(primary_key=True)
    user_auth = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='perfil')
    nombre = models.CharField(max_length=255)
    _email = models.CharField(max_length=255, unique=True, db_column='email_encrypted', default='fake@example.com')
    rut_hash = models.CharField(max_length=128, blank=True, editable=False)
    rut = models.CharField(max_length=12, blank=True, null=True, unique=True, db_index=True)  # <-- CORREGIDO
    rol_id = models.ForeignKey('Rol', on_delete=models.CASCADE)
    activo = models.CharField(max_length=1, default='S')

    @property
    def email(self):
        if not self._email:
            return ''
        try:
            return get_fernet().decrypt(self._email.encode()).decode()
        except Exception:
            return ''

    @email.setter
    def email(self, value):
        self._email = get_fernet().encrypt(value.encode()).decode()

    def set_rut(self, raw_rut: str):
        clean = re.sub(r'[^0-9kK]', '', raw_rut.upper())
        if not clean or len(clean) < 8 or len(clean) > 10:
            raise ValueError("RUT inválido o formato incorrecto")
        cuerpo = clean[:-1]
        dv = clean[-1].upper()
        self.rut_hash = make_password(clean)
        self.rut = f"{cuerpo}-{dv}"  # <-- GUARDA EN 'rut'

    def verify_rut(self, raw_rut: str) -> bool:
        clean = re.sub(r'[^0-9kK]', '', raw_rut.upper())
        return check_password(clean, self.rut_hash)

    def __str__(self):
        return self.nombre or 'Sin nombre'

class Rol(models.Model):
    id_rol = models.AutoField(primary_key=True)
    nombre_rol = models.CharField(max_length=50)
    descripcion_rol = models.TextField()

    def __str__(self):
        return self.nombre_rol

class Permiso(models.Model):
    id_permiso = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=50)
    descripcion_permiso = models.TextField()

    def __str__(self):
        return self.nombre

class RolPermiso(models.Model):
    rol = models.ForeignKey(Rol, on_delete=models.CASCADE)
    permiso = models.ForeignKey(Permiso, on_delete=models.CASCADE)

class InstrumentoNI(models.Model):
    id_instru = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=255)
    regla_es = models.TextField()
    estado = models.CharField(max_length=50)

    def __str__(self):
        return self.nombre

class Factor_Val(models.Model):
    id_factor = models.AutoField(primary_key=True)
    rango_minimo = models.FloatField()
    rango_maximo = models.FloatField()
    descripcion = models.TextField()

    def clean(self):
        if self.rango_minimo >= self.rango_maximo:
            raise ValidationError("El rango mínimo debe ser inferior al rango máximo.")
        super().clean()

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.rango_minimo}-{self.rango_maximo}"

class Calificacion(models.Model):
    calid = models.AutoField(primary_key=True)
    monto = models.FloatField()
    factor = models.FloatField()
    periodo = models.DateField()
    instrumento = models.ForeignKey(InstrumentoNI, on_delete=models.CASCADE)
    estado = models.CharField(max_length=50, default='PENDIENTE')
    fecha_creacion = models.DateField(auto_now_add=True)
    fecha_modificacion = models.DateField(auto_now=True)
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    factor_val_id_factor = models.ForeignKey(Factor_Val, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.instrumento} - {self.periodo}"

class CargaMasiva(models.Model):
    id_cm = models.AutoField(primary_key=True)
    archivo = models.JSONField()
    errores = models.TextField(blank=True)
    calificacion_calid = models.ForeignKey(Calificacion, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"Carga {self.id_cm}"

class Busqueda(models.Model):
    id_busqueda = models.AutoField(primary_key=True)
    criterios_busqueda = models.TextField()
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return f"Búsqueda {self.id_busqueda}"

class Auditoria(models.Model):
    id_Auditoria = models.AutoField(primary_key=True)
    accion = models.CharField(max_length=255)
    Tabla = models.CharField(max_length=255)
    Cambios = models.TextField()
    Fecha = models.DateField(auto_now_add=True)
    ip = models.CharField(max_length=255)
    Firma_Digital = models.CharField(max_length=255)
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.accion} en {self.Tabla} ({self.Fecha})"

    @staticmethod
    def registrar(accion, tabla, cambios, fecha, ip, firma, usuario):
        cambios_mascarados = Auditoria._mask_sensitive(cambios)
        return Auditoria.objects.create(
            accion=accion,
            Tabla=tabla,
            Cambios=cambios_mascarados,
            Fecha=fecha,
            ip=ip,
            Firma_Digital=firma,
            usuario_id_usuario=usuario,
        )

    @staticmethod
    def _mask_sensitive(data: str) -> str:
        data = re.sub(r'\b[\w.-]+@[\w.-]+\.\w{2,}\b', '***@***.tld', data)
        data = re.sub(r'\b\d{4}-\d{4}-\d{4}-(\d{4})\b', r'****-****-****-\1', data)
        return data