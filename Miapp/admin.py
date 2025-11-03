from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import Calificacion, CargaMasiva, Usuario, Rol, Busqueda, Factor_Val, Permiso, InstrumentoNI, Auditoria, RolPermiso, UserAuth

class CalificacionAdmin(admin.ModelAdmin):
    list_display = ['calid', 'monto', 'factor', 'periodo', 'instrumento', 'estado', 
                    'fecha_creacion', 'fecha_modificacion', 'usuario_id_usuario__nombre', 
                    'factor_val_id_factor__descripcion']

class CargaMasivaAdmin(admin.ModelAdmin):
    list_display = ['id_cm', 'archivo', 'errores', 'calificacion_calid']

class UsuarioAdmin(admin.ModelAdmin):
    list_display = ['nombre', 'email', 'rol_id__nombre_rol', 'activo']

class RolAdmin(admin.ModelAdmin):
    list_display = ['nombre_rol', 'descripcion_rol']

class BusquedaAdmin(admin.ModelAdmin):
    list_display = ['id_busqueda', 'criterios_busqueda', 'usuario_id_usuario__nombre']

class Factor_valAdmin(admin.ModelAdmin):
    list_display = ['id_factor', 'rango_minimo', 'rango_maximo', 'descripcion']

class PermisoAdmin(admin.ModelAdmin):
    list_display = ['id_permiso', 'nombre', 'descripcion_permiso']

class InstrumentoNIAdmin(admin.ModelAdmin):
    list_display = ['id_instru', 'nombre', 'regla_es', 'estado']

class AuditoriaAdmin(admin.ModelAdmin):
    list_display = ['id_Auditoria', 'accion', 'Tabla', 'Cambios', 'Fecha', 'ip', 
                    'Firma_Digital', 'usuario_id_usuario__nombre']

class RolPermisoAdmin(admin.ModelAdmin):
    list_display = ['rol', 'permiso']

# Admin para UserAuth con cifrado de contraseña
class UserAuthAdmin(UserAdmin):
    add_form = UserCreationForm
    form = UserChangeForm
    model = UserAuth
    list_display = ('email', 'nombre', 'is_staff', 'is_active', 'is_superuser')
    list_filter = ('is_staff', 'is_active', 'is_superuser')
    search_fields = ('email', 'nombre')
    ordering = ('email',)
    fieldsets = (
        (None, {'fields': ('email', 'nombre', 'password')}),
        ('Permisos', {'fields': ('is_staff', 'is_active', 'is_superuser', 'groups', 'user_permissions')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'nombre', 'password1', 'password2', 'is_staff', 'is_active', 'is_superuser')}
        ),
    )

admin.site.register(Calificacion, CalificacionAdmin)
admin.site.register(CargaMasiva, CargaMasivaAdmin)
admin.site.register(Usuario, UsuarioAdmin)
admin.site.register(Rol, RolAdmin)
admin.site.register(Busqueda, BusquedaAdmin)
admin.site.register(Factor_Val, Factor_valAdmin)
admin.site.register(Permiso, PermisoAdmin)
admin.site.register(InstrumentoNI, InstrumentoNIAdmin)
admin.site.register(Auditoria, AuditoriaAdmin)
admin.site.register(RolPermiso, RolPermisoAdmin)
admin.site.register(UserAuth, UserAuthAdmin)
