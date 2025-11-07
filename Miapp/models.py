import json
import datetime
from django.core.exceptions import ValidationError
from django.db import transaction
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

    def Agregar_rol(self, nombre, descripcion):
        self.nombre_rol = nombre
        self.descripcion_rol = descripcion
        self.save()


    def Eliminar_rol(self):
        self.delete()

    def Listar_permisos(self):
        return self.Listar_permisos.all()
    
    def Actualizar_descripcion(self, nueva_descripcion):
        self.descripcion_rol = nueva_descripcion
        self.save()

class Permiso(models.Model):
    id_permiso = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=50)
    descripcion_permiso = models.TextField()

    def Asignar_permisos_a_rol(self, rol, permisos):
        rol.permisos.add(*permisos)

class RolPermiso(models.Model):
    rol = models.ForeignKey(Rol, on_delete=models.CASCADE)
    permiso = models.ForeignKey(Permiso, on_delete=models.CASCADE)


class InstrumentoNI(models.Model):
    id_instru = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=255)
    regla_es = models.TextField()
    estado = models.CharField(max_length=50)

    def Gestionar(self, nombre=None,
                  regla_es=None,
                  estado=None):
        
        if nombre is not None:
            self.nombre = nombre

        if regla_es is not None:
            self.regla_es = regla_es

        if estado is not None:
            self.estado = estado
        self.save()

        



class Factor_Val(models.Model):
    id_factor = models.AutoField(primary_key=True)
    rango_minimo = models.FloatField()
    rango_maximo = models.FloatField()
    descripcion = models.TextField()

    def validar_factor(self):
        if self.rango_minimo >= self.rango_maximo:
            raise ValueError("El rango minimo debe ser menor que el rango maximo")
        return True
    


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

    @staticmethod
    def Crear_Calificacion(monto, factor, periodo, instrumento, estado, usuario, factor_val):
        return Calificacion.objects.create(
            monto=monto,
            factor=factor,
            periodo=periodo,
            instrumento=instrumento,
            estado=estado,
            usuario_id_usuario=usuario,
            factor_val_id_factor=factor_val
        )
    
    def Eliminar_calificacion(self):
        self.delete


    def Editar_calificacion(self, monto=None,
                            factor=None,
                            periodo=None,
                            estado=None):
        if monto is not None:
            
            self.monto = monto
        
        if factor is not None:

            self.factor = factor

        if periodo is not None:

            self.periodo = periodo

        if estado is not None:
            self.estado = estado
        
        self.save()

        



class CargaMasiva(models.Model):
    id_cm = models.AutoField(primary_key=True)
    archivo = models.JSONField()
    errores = models.TextField()
    calificacion_calid = models.ForeignKey(Calificacion, on_delete=models.CASCADE)

    @staticmethod
    def cargar_desde_archivo(json_data, usuario_id):
        cm = CargaMasiva.objects.create(archivo=json_data)
        try:
            cm.validar_archivo()
            cm._crear_calificaciones(usuario_id)
        except Exception as e:
            cm.errores = str(e)
            cm.save()
        return cm

    def validar_archivo(self):
        errores = []
        for idx, fila in enumerate(self.archivo, start=1):
            try:
                float(fila['monto'])
                int(fila['instrumento_id'])
                int(fila['factor_val_id'])
                datetime.datetime.strptime(fila['periodo'], '%Y-%m-%d')
            except Exception:
                errores.append({'fila': idx, 'error': 'Datos inválidos'})
        if errores:
            self.errores = json.dumps(errores)
            self.save()
            raise ValidationError('Archivo con errores')

    @transaction.atomic
    def _crear_calificaciones(self, usuario_id):
        usuario = UserAuth.objects.get(pk=usuario_id)
        fallos = []
        for idx, fila in enumerate(self.archivo, start=1):
            try:
                Calificacion.objects.create(
                    monto=float(fila['monto']),
                    factor=float(fila.get('factor', 1)),
                    periodo=datetime.datetime.strptime(fila['periodo'], '%Y-%m-%d').date(),
                    instrumento_id=int(fila['instrumento_id']),
                    estado=fila.get('estado', 'PENDIENTE'),
                    usuario_id_usuario=usuario,
                    factor_val_id_factor_id=int(fila['factor_val_id']),
                    fecha_creacion=datetime.date.today(),
                    fecha_modificacion=datetime.date.today()
                )
            except Exception as e:
                fallos.append({'fila': idx, 'error': str(e)})
        if fallos:
            self.errores = json.dumps(fallos)
            self.save()

    def generar_informe_errores(self):
        try:
            return {'status': 'error', 'errores': json.loads(self.errores)}
        except (json.JSONDecodeError, TypeError):
            return {'status': 'ok', 'errores': []}


class Busqueda(models.Model):
    id_busqueda = models.AutoField(primary_key=True)
    criterios_busqueda = models.TextField()
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    @staticmethod
    def Buscar(criterios):
        return Busqueda.objects.filter(criterios_busqueda__icontains=criterios)
    

class Auditoria(models.Model):
    id_Auditoria = models.AutoField(primary_key=True)
    accion = models.CharField(max_length=255)
    Tabla = models.CharField(max_length=255)
    Cambios = models.TextField()
    Fecha = models.DateField()
    ip = models.CharField(max_length=255)
    Firma_Digital = models.CharField(max_length=255)
    usuario_id_usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    @staticmethod
    def Registrar(accion, tabla, cambios, fecha, ip, firma, usuario):
        return Auditoria.objects.create(
            accion = accion,
            Tabla = tabla,
            Cambios = cambios,
            Fecha = fecha,
            ip = ip,
            Firma_digital = firma,
            usuario_id_usuario = usuario

         )