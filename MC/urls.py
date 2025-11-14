"""
URL configuration for MC project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from . import views


urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.login_usuario, name='login'),
    path('inicio/', views.inicio, name='inicio'),
    path('inicioAdmin/', views.inicioAdmin, name='inicioAdmin'),
    path('inicioOperador/', views.inicioOperador, name='inicioOperador'),
    path('filtrar-calificaciones/', views.filtrar_calificaciones_por_rut, name='filtrar_calificaciones'),
    path('operador/crear-calificacion/', views.crear_calificacion, name='crear_calificacion'),
    path('operador/carga-masiva/', views.carga_masiva, name='carga_masiva'),
    path('operador/guardar-calificacion/', views.guardar_calificacion, name='guardar_calificacion'),
    path('operador/guardar-usuario/', views.guardar_usuario, name='guardar_usuario'),
    path('operador/guardar-instrumento/', views.guardar_instrumento, name='guardar_instrumento'),
    path('operador/guardar-rol/', views.guardar_rol, name='guardar_rol'),
    path('operador/filtrar-calificaciones/', views.filtrar_calificaciones, name='filtrar_calificaciones'),

    
    path('admin/eliminar-calificacion/<int:calid>/', views.eliminar_calificacion, name='eliminar_calificacion'),
    path('admin/eliminar-usuario/<int:id_usuario>/', views.eliminar_usuario, name='eliminar_usuario'),
    path('admin/eliminar-instrumento/<int:id_instru>/', views.eliminar_instrumento, name='eliminar_instrumento'),
    path('admin/eliminar-rol/<int:id_rol>/', views.eliminar_rol, name='eliminar_rol'),
    path('admin/guardar-permiso/', views.guardar_permiso, name='guardar_permiso'),
    path('admin/eliminar-permiso/<int:id_permiso>/', views.eliminar_permiso, name='eliminar_permiso'),
        path('admin/visualizar-usuarios/', views.visualizar_usuarios, name='visualizar_usuarios'),
]