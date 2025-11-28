from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import (
    Calificacion, CargaMasiva, Usuario, Rol, Busqueda, Factor_Val,
    Permiso, InstrumentoNI, Auditoria, RolPermiso, UserAuth
)


# ---------------------------
# CALIFICACIÓN
# ---------------------------
class CalificacionAdmin(admin.ModelAdmin):
    list_display = [
        'calid',
        'monto',
        'factor',
        'periodo',
        'instrumento',
        'estado',
        'fecha_creacion',
        'fecha_modificacion',
        'usuario_id_usuario',
        'factor_val_id_factor',
        'eliminado_por',
    ]


# ---------------------------
# CARGA MASIVA
# ---------------------------
class CargaMasivaAdmin(admin.ModelAdmin):
    list_display = [
        'id_cm',
        'archivo',
        'errores',
        'usuario',
        'procesado',
        'fecha',
    ]


# ---------------------------
# USUARIO
# ---------------------------
class UsuarioAdmin(admin.ModelAdmin):
    list_display = [
        'id_usuario',
        'nombre',
        'email',
        'rol_id',
        'activo',
    ]


# ---------------------------
# ROL
# ---------------------------
class RolAdmin(admin.ModelAdmin):
    list_display = [
        'id_rol',
        'nombre_rol',
        'descripcion_rol',
    ]


# ---------------------------
# BÚSQUEDA
# ---------------------------
class BusquedaAdmin(admin.ModelAdmin):
    list_display = [
        'id_busqueda',
        'criterios_busqueda',
        'usuario_id_usuario',
    ]


# ---------------------------
# FACTOR_VAL
# ---------------------------
class FactorValAdmin(admin.ModelAdmin):
    list_display = [
        'id_factor',
        'rango_minimo',
        'rango_maximo',
        'descripcion',
    ]


# ---------------------------
# PERMISO
# ---------------------------
class PermisoAdmin(admin.ModelAdmin):
    list_display = [
        'id_permiso',
        'nombre',
        'descripcion_permiso',
    ]


# ---------------------------
# INSTRUMENTO NO INSCRITO
# ---------------------------
class InstrumentoNIAdmin(admin.ModelAdmin):
    list_display = [
        'id_instru',
        'nombre',
        'regla_es',
        'estado',
    ]


# ---------------------------
# AUDITORÍA
# ---------------------------
class AuditoriaAdmin(admin.ModelAdmin):
    list_display = [
        'id_Auditoria',
        'accion',
        'tabla',
        'cambios',
        'fecha',
        'ip',
        'firma_digital',
        'usuario',
    ]


# ---------------------------
# ROL PERMISO
# ---------------------------
class RolPermisoAdmin(admin.ModelAdmin):
    list_display = [
        'rol',
        'permiso',
    ]


# ---------------------------
# USER AUTH (CUSTOM USER)
# ---------------------------
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
        ('Permisos', {
            'fields': ('is_staff', 'is_active', 'is_superuser', 'groups', 'user_permissions')
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'nombre', 'password1', 'password2',
                       'is_staff', 'is_active', 'is_superuser')}
        ),
    )


# ---------------------------
# REGISTRO EN ADMIN
# ---------------------------
admin.site.register(Calificacion, CalificacionAdmin)
admin.site.register(CargaMasiva, CargaMasivaAdmin)
admin.site.register(Usuario, UsuarioAdmin)
admin.site.register(Rol, RolAdmin)
admin.site.register(Busqueda, BusquedaAdmin)
admin.site.register(Factor_Val, FactorValAdmin)
admin.site.register(Permiso, PermisoAdmin)
admin.site.register(InstrumentoNI, InstrumentoNIAdmin)
admin.site.register(Auditoria, AuditoriaAdmin)
admin.site.register(RolPermiso, RolPermisoAdmin)
admin.site.register(UserAuth, UserAuthAdmin)
