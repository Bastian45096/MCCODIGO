from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from Miapp.forms import LoginUsuarioForm
from Miapp.models import UserAuth
import logging

logger = logging.getLogger(__name__)

def login_usuario(request):
    if request.method == 'POST':
        form = LoginUsuarioForm(request.POST)
        if form.is_valid():
            usuario_input = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, username=usuario_input, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Bienvenido {user.nombre}')
                return redirect('inicio')
            else:
                logger.warning("Login fallido usuario=%s", usuario_input)
                messages.error(request, 'Correo electrónico/nombre o contraseña incorrectos.')
    else:
        form = LoginUsuarioForm()
    return render(request, 'login.html', {'form': form})

@login_required
def inicio(request):
    try:
        perfil = request.user.perfil
        rol_nombre = perfil.rol_id.nombre_rol
    except Exception:
        perfil = None
        rol_nombre = "No Asignado (Perfil no creado)"
    context = {
        'nombre_usuario_login': request.user.nombre,
        'rol_usuario': rol_nombre,
    }
    return render(request, 'inicio.html', context)

def tiene_permisos(request, user_id, permiso_nombre):
    try:
        user = UserAuth.objects.get(id=user_id)
        return JsonResponse({'status': 'success', 'tiene_permiso': user.tiene_permiso(permiso_nombre)})
    except UserAuth.DoesNotExist:
        logger.info("Usuario id=%s no encontrado al verificar permiso", user_id)
        return JsonResponse({'status': 'error', 'message': 'Usuario no encontrado'})

def iniciar_sesion(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Método no permitido'})
    email = request.POST.get('email')
    password = request.POST.get('password')
    user = authenticate(request, email=email, password=password)
    if user is not None:
        login(request, user)
        return JsonResponse({'status': 'success'})
    else:
        logger.warning("Login JSON fallido email=%s", email)
        return JsonResponse({'status': 'error', 'message': 'Credenciales inválidas'})