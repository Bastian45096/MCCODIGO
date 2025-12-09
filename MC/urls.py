from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    # Otras rutas...
    path('admin/eliminar-calificacion/<int:calid>/', views.eliminar_calificacion, name='eliminar_calificacion'),
    path('admin/eliminar-usuario/<int:id_usuario>/', views.eliminar_usuario, name='eliminar_usuario'),
    path('admin/eliminar-instrumento/<int:id_instru>/', views.eliminar_instrumento, name='eliminar_instrumento'),
    path('admin/eliminar-rol/<int:id_rol>/', views.eliminar_rol, name='eliminar_rol'),
    path('admin/eliminar-permiso/<int:id_permiso>/', views.eliminar_permiso, name='eliminar_permiso'),
   
    path('admin/actualizar-calificacion/<int:calid>/', views.actualizar_calificacion , name='actualizar_calificacion'),
    path('admin/actualizar-usuario/<int:id_usuario>/', views.actualizar_usuario, name='actualizar_usuario'),
    path('admin/actualizar-instrumento/<int:id_instru>/', views.actualizar_instrumento, name='actualizar_instrumento'),
    
    path('filtrar-calificaciones/', views.filtrar_calificaciones, name='filtrar_calificaciones'),
    path('filtrar-calificaciones-por-rut/', views.filtrar_calificaciones_por_rut, name='filtrar_calificaciones_por_rut'),
    
    path('operador/crear-calificacion/', views.crear_calificacion, name='crear_calificacion'),
    path('operador/carga-masiva/', views.carga_masiva, name='carga_masiva'),
    path('operador/guardar-calificacion/', views.guardar_calificacion, name='guardar_calificacion'),
    path('operador/guardar-usuario/', views.guardar_usuario, name='guardar_usuario'),
    path('operador/guardar-instrumento/', views.guardar_instrumento, name='guardar_instrumento'),
    path('operador/guardar-rol/', views.guardar_rol, name='guardar_rol'),
    
    path('admin/guardar-permiso/', views.guardar_permiso, name='guardar_permiso'),
    
    path('login/', views.login_usuario, name='login'),
    path('inicio/', views.inicio, name='inicio'),
    path('inicioAdmin/', views.inicioAdmin, name='inicioAdmin'),
    path('inicioOperador/', views.inicioOperador, name='inicioOperador'),
    path('visualizar-usuarios/', views.visualizar_usuarios, name='visualizar_usuarios'),
    path('logout/', views.logout_usuario, name='logout'),
    path('', views.principal, name='principal'),
    path('gestionar_asignacion_permisos/', views.asignar_permisos, name='gestionar_asignacion_permisos'),
    path('gestionar_asignacion_permisos_editacion/', views.asignar_permisos_editacion, name='gestionar_asignacion_permisos_editacion'),
    path('crear-factorv/', views.crear_factorv, name='crear_factorv'),
    path('editar-factorv/', views.editar_factorv, name='editar_factorv'),
    path('actualizar-factorv/<int:id_factor>/', views.actualizar_factorv, name='actualizar_factorv'),
    path('eliminar-factorv/<int:id_factor>/', views.eliminar_factorv, name='eliminar_factorv'),
    path('asignar/todos/', views.asignar_todos_permisos, name='asignar_todos_permisos'),
    path('asignar/quitar-todos/', views.quitar_todos_permisos, name='quitar_todos_permisos'),
    path('admin/eliminar-asignacion/<int:asignacion_id>/', views.eliminar_asignacion_individual, name='eliminar_asignacion_individual'),
    path('admin/', admin.site.urls),
]