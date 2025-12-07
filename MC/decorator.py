from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required


def operador_tiene_permiso(request, permiso_nombre):
    try:
        return request.user.perfil.tiene_permiso(permiso_nombre)
    except AttributeError:
        return False

def requiere_permiso_operador(permiso_nombre):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not operador_tiene_permiso(request, permiso_nombre):
                messages.error(request, f'No tienes permiso para realizar esta acción: {permiso_nombre}')
                return redirect('/inicioOperador/')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def requiere_permiso_administrador(view_func):
    def wrap(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        try:
            if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador':
                return view_func(request, *args, **kwargs)
        except:
            pass
            
        messages.error(request, 'No tienes permisos de administrador')
        return redirect('login')
    return wrap
