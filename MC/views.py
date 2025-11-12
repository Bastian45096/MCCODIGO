from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from Miapp.forms import LoginUsuarioForm
from Miapp.models import UserAuth, Usuario, Calificacion
import logging
import re
import datetime

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
                try:
                    perfil = user.perfil
                    rol = perfil.rol_id.nombre_rol.lower()
                    nombre_mostrar = user.nombre
                except Exception:
                    perfil = None
                    rol = 'cliente'
                    nombre_mostrar = user.nombre

                if rol == 'administrador':
                    messages.success(request, 'Bienvenido, Administrador')
                    return redirect('inicioAdmin')
                elif rol == 'operador':
                    messages.success(request, 'Bienvenido, Operador')
                    return redirect('inicioOperador')
                else:
                    messages.success(request, f'Bienvenido, {nombre_mostrar}')
                    return redirect('inicio')
            else:
                logger.warning("Login fallido usuario=%s", usuario_input)
                messages.error(request, 'Correo electrónico/nombre o contraseña incorrectos.')
    else:
        form = LoginUsuarioForm()
    return render(request, 'login.html', {'form': form})

@login_required
def inicioAdmin(request):
    return render(request, 'inicioAdmin.html')

@login_required
def inicioOperador(request):
    return render(request, 'inicioOperador.html')

@login_required
def inicio(request):
    perfil = None
    rol_nombre = "Cliente"
    nombre_usuario = request.user.nombre
    
    calificaciones = []
    mensaje = None
    rut_filtrado = None
    
    try:
        perfil = request.user.perfil
        rol_nombre = perfil.rol_id.nombre_rol
    except Usuario.DoesNotExist:
        mensaje = "Tu cuenta no tiene un perfil de cliente asociado."
        
    context = {
        'nombre_usuario_login': nombre_usuario,
        'rol_usuario': rol_nombre,
        'calificaciones': calificaciones,
        'mensaje': mensaje,
    }
    
    if perfil and request.method == 'GET' and 'rut' in request.GET:
        rut_input = request.GET.get('rut', '').strip()
        
      
        clean_rut_ingresado = re.sub(r'[^0-9kK]', '', rut_input.upper())
        
        if len(clean_rut_ingresado) < 8 or len(clean_rut_ingresado) > 10:
            context['mensaje'] = 'RUT inválido. Por favor, ingrésalo correctamente.'
        else:
            # Formatea solo para mostrar en la plantilla
            rut_formateado_display = f"{clean_rut_ingresado[:-1]}-{clean_rut_ingresado[-1].upper()}"
            context['rut_filtrado'] = rut_formateado_display
            
            # Limpieza del RUT DE LA BD
            clean_rut_bd = re.sub(r'[^0-9kK]', '', perfil.rut.upper())
            
            # Comparación de cadenas limpias
            if clean_rut_bd != clean_rut_ingresado:
                context['mensaje'] = 'El RUT ingresado no coincide con tu RUT registrado.'
            else:
                
                
                calificaciones_qs = Calificacion.objects.filter(
                    usuario_id_usuario=request.user 
                ).select_related('instrumento', 'factor_val_id_factor').order_by('-periodo')
                
                if calificaciones_qs.exists():
                    context['calificaciones'] = [
                        {
                            'instrumento': c.instrumento.nombre,
                            'periodo': c.periodo.strftime('%d/%m/%Y'),
                            'monto': f"${c.monto:,.0f}",
                            'factor': c.factor,
                            'estado': c.estado,
                        }
                        for c in calificaciones_qs
                    ]
                else:
                    context['mensaje'] = 'No se encontraron calificaciones para el RUT ingresado.'
                    
    return render(request, 'inicio.html', context)

@require_POST
@login_required
def filtrar_calificaciones_por_rut(request):
    return JsonResponse({'error': 'Función de filtrado con POST obsoleta.'}, status=400)

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
