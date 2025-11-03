from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.conf import settings


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
    user_auth = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='perfil'
    )
    nombre = models.CharField(max_length=255)
    email = models.EmailField(max_length=255, unique=True)
    rol_id = models.ForeignKey('Rol', on_delete=models.CASCADE)
    activo = models.CharField(max_length=1)

    def __str__(self):
        return self.nombre


class Rol(models.Model):
    id_rol = models.AutoField(primary_key=True)
    nombre_rol = models.CharField(max_length=50)
    descripcion_rol = models.TextField()


class Permiso(models.Model):
    id_permiso = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=50)
    descripcion_permiso = models.TextField()


class RolPermiso(models.Model):
    rol = models.ForeignKey(Rol, on_delete=models.CASCADE)
    permiso = models.ForeignKey(Permiso, on_delete=models.CASCADE)


class InstrumentoNI(models.Model):
    id_instru = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=255)
    regla_es = models.TextField()
    estado = models.CharField(max_length=50)


class Factor_Val(models.Model):
    id_factor = models.AutoField(primary_key=True)
    rango_minimo = models.FloatField()
    rango_maximo = models.FloatField()
    descripcion = models.TextField()


class Calificacion(models.Model):
    calid = models.AutoField(primary_key=True)
    monto = models.FloatField()
    factor = models.FloatField()
    periodo = models.DateField()
    instrumento = models.ForeignKey(InstrumentoNI, on_delete=models.CASCADE)
    estado = models.CharField(max_length=50)
    fecha_creacion = models.DateField()
    fecha_modificacion = models.DateField()
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    factor_val_id_factor = models.ForeignKey(Factor_Val, on_delete=models.CASCADE)


class CargaMasiva(models.Model):
    id_cm = models.AutoField(primary_key=True)
    archivo = models.BinaryField()
    errores = models.TextField()
    calificacion_calid = models.ForeignKey(Calificacion, on_delete=models.CASCADE)


class Busqueda(models.Model):
    id_busqueda = models.AutoField(primary_key=True)
    criterios_busqueda = models.TextField()
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)


class Auditoria(models.Model):
    id_Auditoria = models.AutoField(primary_key=True)
    accion = models.CharField(max_length=255)
    Tabla = models.CharField(max_length=255)
    Cambios = models.TextField()
    Fecha = models.DateField()
    ip = models.CharField(max_length=255)
    Firma_Digital = models.CharField(max_length=255)
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)