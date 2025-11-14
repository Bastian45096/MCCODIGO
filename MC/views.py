from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from Miapp.forms import LoginUsuarioForm
from Miapp.models import UserAuth, Usuario, Calificacion, InstrumentoNI, Factor_Val, CargaMasiva, Rol, Permiso
import logging
import re
import datetime
import json

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
                    rol = perfil.rol_id.nombre_rol
                    nombre_mostrar = user.nombre
                except Exception:
                    perfil = None
                    rol = 'cliente'
                    nombre_mostrar = user.nombre
                if rol.lower() == 'administrador':
                    messages.success(request, 'Bienvenido, Administrador')
                    return redirect('inicioAdmin')
                elif rol.lower() == 'operador':
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
    instrumentos   = InstrumentoNI.objects.filter(estado='ACTIVO')
    roles          = Rol.objects.all()
    usuarios       = Usuario.objects.select_related('user_auth', 'rol_id').filter(activo='S')
    calificaciones = Calificacion.objects.filter(estado='ACTIVO')

    seccion = request.GET.get('seccion')
    accion  = request.GET.get('accion')
    obj_id  = request.GET.get('obj_id')

    obj = None

   
    if seccion == 'calificacion' and accion == 'editar' and obj_id:
        obj = Calificacion.objects.select_related('instrumento').get(calid=obj_id)
    elif seccion == 'usuario' and accion == 'editar' and obj_id:
        obj = Usuario.objects.select_related('rol_id').get(id_usuario=obj_id)
    elif seccion == 'instrumento' and accion == 'editar' and obj_id:
        obj = InstrumentoNI.objects.get(id_instru=obj_id)
    elif seccion == 'rol' and accion == 'editar' and obj_id:
        obj = Rol.objects.get(id_rol=obj_id)

    return render(request, 'inicioOperador.html', {
        'instrumentos':   instrumentos,
        'roles':          roles,
        'usuarios':       usuarios,
        'calificaciones': calificaciones,
        'seccion':        seccion,
        'accion':         accion,
        'obj':            obj,
        'obj_id':         obj_id,
    })

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
            rut_formateado_display = f"{clean_rut_ingresado[:-1]}-{clean_rut_ingresado[-1].upper()}"
            context['rut_filtrado'] = rut_formateado_display
            clean_rut_bd = re.sub(r'[^0-9kK]', '', perfil.rut.upper())
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

@login_required
def crear_calificacion(request):
    if request.method == 'POST':
        try:
            monto = float(request.POST.get('monto'))
            factor = float(request.POST.get('factor'))
            periodo = datetime.datetime.strptime(request.POST.get('periodo'), '%Y-%m').date()
            instru = InstrumentoNI.objects.get(pk=request.POST.get('instrumento'))
            fv = Factor_Val.objects.get(rango_minimo__lte=factor, rango_maximo__gte=factor)
        except Exception as e:
            messages.error(request, f'Datos incorrectos: {e}')
            return redirect('inicioOperador')
        Calificacion.objects.create(
            monto=monto,
            factor=factor,
            periodo=periodo,
            instrumento=instru,
            estado='ACTIVO',
            usuario_id_usuario=request.user,
            factor_val_id_factor=fv
        )
        messages.success(request, 'Calificación creada correctamente.')
        return redirect('inicioOperador')
    return redirect('inicioOperador')

@login_required
def carga_masiva(request):
    if request.method == 'POST' and request.FILES.get('archivo'):
        try:
            archivo = request.FILES['archivo']
            data = json.load(archivo)
            CargaMasiva.objects.create(archivo=data, errores='')
            messages.success(request, 'Archivo cargado y registrado.')
        except Exception as e:
            messages.error(request, f'Error en el archivo: {e}')
        return redirect('inicioOperador')
    return redirect('inicioOperador')

@login_required
def guardar_calificacion(request):
    if request.method == 'POST':
        try:
            monto   = float(request.POST.get('monto'))
            factor  = float(request.POST.get('factor'))
            periodo = datetime.datetime.strptime(request.POST.get('periodo'), '%Y-%m').date()
            instru  = InstrumentoNI.objects.get(pk=request.POST.get('instrumento'))
            fv      = Factor_Val.objects.get(rango_minimo__lte=factor, rango_maximo__gte=factor)
            Calificacion.objects.create(
                monto=monto, factor=factor, periodo=periodo,
                instrumento=instru, estado='ACTIVO',
                usuario_id_usuario=request.user,
                factor_val_id_factor=fv)
            messages.success(request, 'Calificación guardada.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
        return redirect('inicioOperador')
    return redirect('inicioOperador')

@login_required
def guardar_usuario(request):
    if request.method == 'POST':
        try:
            nombre   = request.POST.get('nombre')
            rut      = request.POST.get('rut')
            email    = request.POST.get('email')
            rol_id   = request.POST.get('rol')
            user = UserAuth.objects.create_user(
                nombre=nombre,
                email=email,
                password=rut
            )
            usuario = Usuario.objects.create(
                user_auth=user,
                nombre=nombre,
                rol_id_id=rol_id,
                activo='S'
            )
            usuario.set_rut(rut)
            usuario.email = email
            usuario.save()
            messages.success(request, 'Usuario actualizado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
        return redirect('inicioOperador')
    return redirect('inicioOperador')

@login_required
def guardar_instrumento(request):
    if request.method == 'POST':
        try:
            pk       = request.POST.get('id_instru')
            nombre   = request.POST.get('nombre')
            regla_es = request.POST.get('regla_es')
            estado   = request.POST.get('estado')
            if pk:
                InstrumentoNI.objects.filter(pk=pk).update(
                    nombre=nombre,
                    regla_es=regla_es,
                    estado=estado
                )
                messages.success(request, 'Instrumento actualizado.')
            else:
                InstrumentoNI.objects.create(
                    nombre=nombre,
                    regla_es=regla_es,
                    estado=estado
                )
                messages.success(request, 'Instrumento creado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
        return redirect('inicioOperador')
    return redirect('inicioOperador')

@login_required
def guardar_rol(request):
    if request.method == 'POST':
        try:
            pk          = request.POST.get('id_rol')
            nombre      = request.POST.get('nombre_rol')
            descripcion = request.POST.get('descripcion_rol')
            if pk:
                Rol.objects.filter(pk=pk).update(
                    nombre_rol=nombre,
                    descripcion_rol=descripcion
                )
                messages.success(request, 'Rol actualizado.')
            else:
                Rol.objects.create(
                    nombre_rol=nombre,
                    descripcion_rol=descripcion
                )
                messages.success(request, 'Rol creado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
        return redirect('inicioOperador')
    return redirect('inicioOperador')

@login_required
def inicioAdmin(request):
    instrumentos   = InstrumentoNI.objects.filter(estado='ACTIVO')
    roles          = Rol.objects.all()
    usuarios       = Usuario.objects.select_related('user_auth', 'rol_id').filter(activo='S')
    calificaciones = Calificacion.objects.filter(estado='ACTIVO')
    permisos       = Permiso.objects.all()

    seccion = request.GET.get('seccion')
    accion  = request.GET.get('accion')
    obj_id  = request.GET.get('obj_id')

    obj = None

    if seccion == 'calificacion' and accion == 'editar' and obj_id:
        obj = Calificacion.objects.select_related('instrumento').get(calid=obj_id)
    elif seccion == 'usuario' and accion == 'editar' and obj_id:
        obj = Usuario.objects.select_related('rol_id').get(id_usuario=obj_id)
    elif seccion == 'instrumento' and accion == 'editar' and obj_id:
        obj = InstrumentoNI.objects.get(id_instru=obj_id)
    elif seccion == 'rol' and accion == 'editar' and obj_id:
        obj = Rol.objects.get(id_rol=obj_id)
    elif seccion == 'permiso' and accion == 'editar' and obj_id:
        obj = Permiso.objects.get(id_permiso=obj_id)

    return render(request, 'inicioAdmin.html', {
        'instrumentos':   instrumentos,
        'roles':          roles,
        'usuarios':       usuarios,
        'calificaciones': calificaciones,
        'permisos':       permisos,
        'seccion':        seccion,
        'accion':         accion,
        'obj':            obj,
        'obj_id':         obj_id,
    })

@login_required
def eliminar_calificacion(request, calid):
    Calificacion.objects.filter(calid=calid).delete()
    messages.success(request, 'Calificación eliminada.')
    return redirect('inicioAdmin')

@login_required
def eliminar_usuario(request, id_usuario):
    Usuario.objects.filter(id_usuario=id_usuario).delete()
    messages.success(request, 'Usuario eliminado.')
    return redirect('inicioAdmin')

@login_required
def eliminar_instrumento(request, id_instru):
    InstrumentoNI.objects.filter(id_instru=id_instru).delete()
    messages.success(request, 'Instrumento eliminado.')
    return redirect('inicioAdmin')

@login_required
def eliminar_rol(request, id_rol):
    Rol.objects.filter(id_rol=id_rol).delete()
    messages.success(request, 'Rol eliminado.')
    return redirect('inicioAdmin')

@login_required
def guardar_permiso(request):
    if request.method == 'POST':
        try:
            pk = request.POST.get('id_permiso')
            nombre = request.POST.get('nombre')
            descripcion = request.POST.get('descripcion')
            if pk:
                Permiso.objects.filter(pk=pk).update(nombre=nombre, descripcion_permiso=descripcion)
                messages.success(request, 'Permiso actualizado.')
            else:
                Permiso.objects.create(nombre=nombre, descripcion_permiso=descripcion)
                messages.success(request, 'Permiso creado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
        return redirect('inicioAdmin')
    return redirect('inicioAdmin')

@login_required
def eliminar_permiso(request, id_permiso):
    Permiso.objects.filter(id_permiso=id_permiso).delete()
    messages.success(request, 'Permiso eliminado.')
    return redirect('inicioAdmin')

@login_required
def filtrar_calificaciones(request):
    rut = request.GET.get('rut')
    qs  = Calificacion.objects.filter(
        usuario_id_usuario__perfil__rut=rut,
        estado='ACTIVO'
    ).select_related('instrumento')
    return render(request, 'filtrar_resultado.html', {'calificaciones': qs})

@login_required
def visualizar_usuarios(request):
    operadores = Usuario.objects.filter(rol_id__nombre_rol__iexact='operador', activo='S')
    clientes = Usuario.objects.filter(rol_id__nombre_rol__iexact='cliente', activo='S')

    return render(request, 'visualizar_usuarios.html', {
        'operadores': operadores,
        'clientes': clientes,
    })
