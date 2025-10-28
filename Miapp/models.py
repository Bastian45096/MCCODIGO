from django.db import models

class Usuario(models.Model):
    id_usuario = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=255)
    email = models.EmailField(max_length=255)
    rol_id = models.ForeignKey('Rol', on_delete=models.CASCADE)
    activo = models.CharField(max_length=1)
    

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

class Calificacion(models.Model):
    calid = models.AutoField(primary_key=True)
    monto = models.FloatField()
    factor = models.FloatField()
    periodo = models.DateField()
    instrumento = models.ForeignKey(InstrumentoNI, on_delete=models.CASCADE)
    estado = models.CharField(max_length=50)
    fecha_creacion = models.DateField()
    fecha_modificacion = models.DateField()
    usuario_id_usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    factor_val_id_factor = models.ForeignKey('Factor_Val', on_delete=models.CASCADE)

class Factor_Val(models.Model):
    id_factor = models.AutoField(primary_key=True)
    rango_minimo = models.FloatField()
    rango_maximo = models.FloatField()
    descripcion = models.TextField()

class CargaMasiva(models.Model):
    id_cm = models.AutoField(primary_key=True)
    archivo = models.BinaryField()
    errores = models.TextField()
    calificacion_calid = models.ForeignKey(Calificacion, on_delete=models.CASCADE)

class Busqueda(models.Model):
    id_busqueda = models.AutoField(primary_key=True)
    criterios_busqueda = models.TextField()
    usuario_id_usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)

class Auditoria(models.Model):
    id_Auditoria = models.AutoField(primary_key=True)
    accion = models.CharField(max_length=255)
    Tabla = models.CharField(max_length=255)
    Cambios = models.TextField()
    Fecha = models.DateField()
    ip = models.CharField(max_length=255)
    Firma_Digital = models.CharField(max_length=255)
    usuario_id_usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)
