from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from ..Miapp.forms import Login_U, Registrar_U

# Create your views here.

def login(request):
    if request.method == 'POST':

        form = Login_U(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email_usuario']
            contraseña_usuario = form.cleaned_data['contraseña_usuario']
            User = authenticate(request, email=email, contraseña_usuario=contraseña_usuario)
            if User is not None:
                login(request, User)
                return redirect('Inicio')

            else:
                form.add_error(None, 'Los datos no existen o no concuerdan')
    else:
        form = Login_U()
    return render(request,'login.html')

