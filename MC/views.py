from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from Miapp.forms import LoginUsuarioForm

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
