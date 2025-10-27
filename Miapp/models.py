from django.db import models

# Create your models here.

class Busqueda:
    Id_Busqueda = models.BigIntegerField(primary_key=True)
    Criterios_Busqueda = models.TextField()
    

class Usuario:
    ID_Usuario = models.BigIntegerField(primary_key=True)
    Nombre = models.CharField(max_length=255)
    Email = models.CharField(max_length=255)
    Activo = models.BooleanField()



class Calificacion_Tributaria:
    CallID = models.BigIntegerField(primary_key=True)
    Monto = models.FloatField()
    Factor = models.FloatField()
    Periodo = models.DateField()
    Instrumento = models.CharField(max_length=255)
    Estado = models.CharField(max_length=50)
    Fecha_Creacion = models.DateTimeField()
    Fecha_Modificacion = models.DateTimeField()

class Rol:

    ID_Rol = models.BigIntegerField(primary_key=True)
    Nombre_Rol = models.CharField(max_length=50)
    Descripcion = models.TextField()

class Permiso:

    ID_Permiso = models.BigIntegerField(primary_key=True)
    Nombre = models.CharField(max_length=50)
    Descripcion = models.TextField()

class InstrumentoNI:
    
    ID_Instru = models.BigIntegerField(primary_key=True)
    Nombre = models.CharField(max_length=255)
    Reglas_especiales = models.TextField()
    Estado = models.CharField(max_length=50)
    _
class Auditoria:
    id_Auditoria = models.BigIntegerField(primary_key=True)
    accion = models.CharField(max_length=255)
    Tabla = models.CharField(max_length=255)
    Cambios = models.JSONField()
    Fecha = models.DateTimeField()
    ip = models.CharField(max_length=255)
    Firma_Digital = models.CharField(max_length=255)