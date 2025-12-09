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
    rut = models.CharField(max_length=12, unique=True, db_index=True)
    rol_id = models.ForeignKey('Rol', on_delete=models.PROTECT)
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
        self.rut = f"{cuerpo}-{dv}"


    def verify_rut(self, raw_rut: str) -> bool:
        clean = re.sub(r'[^0-9kK]', '', raw_rut.upper())
        if not clean or len(clean) < 8 or len(clean) > 10:
            return False
        cuerpo = clean[:-1]
        dv = clean[-1].upper()
        formatted_rut = f"{cuerpo}-{dv}"
        return formatted_rut == self.rut


    def tiene_permiso(self, permiso_nombre: str) -> bool:
        return RolPermiso.objects.filter(
            rol=self.rol_id,
            permiso__nombre=permiso_nombre
        ).exists()

    def __str__(self):
        return self.nombre or 'Sin nombre'

class Rol(models.Model):
    id_rol = models.AutoField(primary_key=True)
    nombre_rol = models.CharField(max_length=50, unique=True)
    descripcion_rol = models.TextField(blank=True)

    def __str__(self):
        return self.nombre_rol

class Permiso(models.Model):
    id_permiso = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=50, unique=True)
    descripcion_permiso = models.TextField(blank=True)

    def __str__(self):
        return self.nombre

class RolPermiso(models.Model):
    rol = models.ForeignKey(Rol, on_delete=models.CASCADE)
    permiso = models.ForeignKey(Permiso, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('rol', 'permiso')

class InstrumentoNI(models.Model):
    id_instru = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=255)
    regla_es = models.TextField(blank=True)
    estado = models.CharField(max_length=10, default='ACTIVO', choices=[('ACTIVO','ACTIVO'),('INACTIVO','INACTIVO')])

    def __str__(self):
        return self.nombre

class Factor_Val(models.Model):
    id_factor = models.AutoField(primary_key=True)
    rango_minimo = models.DecimalField(max_digits=12, decimal_places=1)
    rango_maximo = models.DecimalField(max_digits=12, decimal_places=1)
    descripcion = models.TextField(blank=True)
    
    def clean(self):
        if self.rango_minimo >= self.rango_maximo:
            raise ValidationError("El rango mínimo debe ser inferior al rango máximo.")
        super().clean()

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.rango_minimo} - {self.rango_maximo}"

class Calificacion(models.Model):
    ESTADOS = [('ACTIVO','ACTIVO'), ('ELIMINADO','ELIMINADO'), ('PENDIENTE','PENDIENTE')]
    
    calid = models.AutoField(primary_key=True)
    monto = models.DecimalField(max_digits=18, decimal_places=1)
    factor = models.DecimalField(max_digits=10, decimal_places=1)
    periodo = models.DateField()
    instrumento = models.ForeignKey(InstrumentoNI, on_delete=models.PROTECT)
    estado = models.CharField(max_length=10, choices=ESTADOS, default='ACTIVO')
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_modificacion = models.DateTimeField(auto_now=True)
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='calificaciones')
    factor_val_id_factor = models.ForeignKey(Factor_Val, on_delete=models.PROTECT)
    eliminado_por = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, 
                                     related_name='calificaciones_eliminadas', on_delete=models.SET_NULL)
    fecha_eliminacion = models.DateTimeField(null=True, blank=True)

    def delete(self, *args, **kwargs):
        self.estado = 'ELIMINADO'
        if kwargs.get('user'):
            self.eliminado_por = kwargs.get('user')
        self.fecha_eliminacion = datetime.datetime.now()
        self.save()

    def hard_delete(self):
        super().delete()

    class Meta:
        indexes = [
            models.Index(fields=['periodo']),
            models.Index(fields=['instrumento']),
            models.Index(fields=['estado']),
            models.Index(fields=['usuario_id_usuario']),
            models.Index(fields=['monto']),
        ]
        permissions = [
            ("puede_crear_calificacion", "Puede crear calificación"),
            ("puede_editar_calificacion", "Puede editar calificación"),
            ("puede_eliminar_calificacion", "Puede eliminar calificación"),
            ("puede_ver_todas_calificaciones", "Puede ver todas las calificaciones"),
            ("puede_carga_masiva", "Puede realizar carga masiva"),
        ]

    def __str__(self):
        return f"{self.instrumento} - {self.periodo}"

class CargaMasiva(models.Model):
    id_cm = models.AutoField(primary_key=True)
    archivo = models.FileField(upload_to='cargas_masivas/%Y/%m/%d/')
    errores = models.TextField(blank=True)
    procesado = models.BooleanField(default=False)
    fecha = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)

    def __str__(self):
        return f"Carga {self.id_cm} - {self.fecha.date() if self.fecha else 'N/A'}"

class Busqueda(models.Model):
    id_busqueda = models.AutoField(primary_key=True)
    criterios_busqueda = models.TextField()
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return f"Búsqueda {self.id_busqueda}"

class Auditoria(models.Model):
    id_Auditoria = models.AutoField(primary_key=True)
    accion = models.CharField(max_length=50)
    tabla = models.CharField(max_length=50, null=True, blank=True)
    cambios = models.TextField()
    fecha = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    firma_digital = models.CharField(max_length=255)
    usuario = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)

    @staticmethod
    def registrar(accion, tabla, cambios, request=None):
        usuario = request.user if request and request.user.is_authenticated else None
        ip = request.META.get('REMOTE_ADDR') if request else None
        cambios_mascarados = Auditoria._mask_sensitive(str(cambios))
        Auditoria.objects.create(
            accion=accion,
            tabla=tabla,
            cambios=cambios_mascarados,
            ip=ip,
            firma_digital=f"user:{usuario.id if usuario else 'anon'}",
            usuario=usuario,
        )

    @staticmethod
    def _mask_sensitive(data: str) -> str:
        data = re.sub(r'\b[\w.-]+@[\w.-]+\.\w{2,}\b', '***@***.tld', data)
        data = re.sub(r'\b\d{8,9}-[\dkK]\b', '********-K', data)
        return data

    def __str__(self):
        return f"{self.accion} en {self.tabla} ({self.fecha})"
    