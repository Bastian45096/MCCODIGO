from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from Miapp.forms import LoginUsuarioForm
from Miapp.models import (UserAuth, Usuario, Calificacion, InstrumentoNI,
                          Factor_Val, CargaMasiva, Rol, Permiso, Auditoria)
import logging
import re
import datetime
import json
from django.contrib.auth import logout
from datetime import date
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# ---------- VALIDACIÓN AUXILIAR ----------
def validar_calificacion(monto, factor, periodo):
    errores = []
    if monto <= 0:
        errores.append("El monto debe ser mayor a 0 (ejemplo: 500000).")
    if factor <= 0:
        errores.append("El factor debe ser mayor a 0 (ejemplo: 1.5).")
    if periodo > date.today():
        errores.append("La fecha del período no puede ser futura. Ejemplo válido: 2025-05.")
    return errores

# ---- FUNCIÓN AUXILIAR PARA REDIRIGIR AL LISTADO DE CALIFICACIONES ----
def _back_to_cal_list(request):
    base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
    query = urlencode({'seccion': 'calificacion'})
    return redirect(f'/{base}/?{query}')

# ---- FUNCIÓN AUXILIAR PARA REDIRIGIR AL LISTADO DE USUARIOS ----
def _back_to_user_list(request):
    base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
    query = urlencode({'seccion': 'usuario'})
    return redirect(f'/{base}/?{query}')

# ---- FUNCIÓN AUXILIAR PARA REDIRIGIR AL LISTADO DE INSTRUMENTOS ----
def _back_to_instrument_list(request):
    base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
    query = urlencode({'seccion': 'instrumento'})
    return redirect(f'/{base}/?{query}')

# ---- FUNCIÓN AUXILIAR PARA REDIRIGIR AL LISTADO DE ROLES ----
def _back_to_rol_list(request):
    base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
    query = urlencode({'seccion': 'rol'})
    return redirect(f'/{base}/?{query}')

# -----------------------------------------

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
    instrumentos = InstrumentoNI.objects.filter(estado='ACTIVO')
    roles = Rol.objects.all()
    usuarios = Usuario.objects.select_related('user_auth', 'rol_id').filter(activo='S')
    calificaciones = Calificacion.objects.filter(estado='ACTIVO')
    permisos = Permiso.objects.all()
    factor_vals = Factor_Val.objects.all()

    seccion = request.GET.get('seccion')
    accion = request.GET.get('accion')
    obj_id = request.GET.get('obj_id')

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
    elif seccion == 'usuario' and accion == 'crear':
        return render(request, 'inicioAdmin.html', {
            'instrumentos': instrumentos,
            'roles': roles,
            'usuarios': usuarios,
            'calificaciones': calificaciones,
            'permisos': permisos,
            'factor_vals': factor_vals,
            'seccion': seccion,
            'accion': accion,
            'obj': obj,
            'obj_id': obj_id,
            'crear_usuario': True
        })
    elif seccion == 'instrumento' and accion == 'crear':
        return render(request, 'inicioAdmin.html', {
            'instrumentos': instrumentos,
            'roles': roles,
            'usuarios': usuarios,
            'calificaciones': calificaciones,
            'permisos': permisos,
            'factor_vals': factor_vals,
            'seccion': seccion,
            'accion': accion,
            'obj': obj,
            'obj_id': obj_id,
            'crear_instrumento': True
        })
    elif seccion == 'rol' and accion == 'crear':
        return render(request, 'inicioAdmin.html', {
            'instrumentos': instrumentos,
            'roles': roles,
            'usuarios': usuarios,
            'calificaciones': calificaciones,
            'permisos': permisos,
            'factor_vals': factor_vals,
            'seccion': seccion,
            'accion': accion,
            'obj': obj,
            'obj_id': obj_id,
            'crear_rol': True
        })
    elif seccion == 'rol' and accion == 'editar' and obj_id:
        return render(request, 'inicioAdmin.html', {
            'instrumentos': instrumentos,
            'roles': roles,
            'usuarios': usuarios,
            'calificaciones': calificaciones,
            'permisos': permisos,
            'factor_vals': factor_vals,
            'seccion': seccion,
            'accion': accion,
            'obj': obj,
            'obj_id': obj_id,
            'editar_rol': True
        })

    return render(request, 'inicioAdmin.html', {
        'instrumentos': instrumentos,
        'roles': roles,
        'usuarios': usuarios,
        'calificaciones': calificaciones,
        'permisos': permisos,
        'factor_vals': factor_vals,
        'seccion': seccion,
        'accion': accion,
        'obj': obj,
        'obj_id': obj_id,
    })

@login_required
def inicioOperador(request):
    instrumentos = InstrumentoNI.objects.filter(estado='ACTIVO')
    roles = Rol.objects.filter(nombre_rol__iexact='Cliente')
    usuarios = Usuario.objects.select_related('user_auth', 'rol_id').filter(activo='S')
    calificaciones = Calificacion.objects.filter(estado='ACTIVO')
    factor_vals = Factor_Val.objects.all()

    seccion = request.GET.get('seccion')
    accion = request.GET.get('accion')
    obj_id = request.GET.get('obj_id')

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
        'instrumentos': instrumentos,
        'roles': roles,
        'usuarios': usuarios,
        'calificaciones': calificaciones,
        'factor_vals': factor_vals,
        'seccion': seccion,
        'accion': accion,
        'obj': obj,
        'obj_id': obj_id,
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

def get_redirect_url(request):
    try:
        perfil = request.user.perfil
        rol = perfil.rol_id.nombre_rol.lower()
        if rol == 'administrador':
            return 'inicioAdmin'
        elif rol == 'operador':
            return 'inicioOperador'
    except Exception:
        pass
    return 'inicio'

# ---------- CREAR CALIFICACIÓN (con validación) ----------
@login_required
def crear_calificacion(request):
    if request.method == 'POST':
        try:
            monto = float(request.POST.get('monto'))
            factor = float(request.POST.get('factor'))
            periodo = datetime.datetime.strptime(request.POST.get('periodo'), '%Y-%m').date()

            errores = validar_calificacion(monto, factor, periodo)
            if errores:
                for e in errores:
                    messages.error(request, e)
                return _back_to_cal_list(request)

            instru = InstrumentoNI.objects.get(pk=request.POST.get('instrumento'))
            fv = Factor_Val.objects.get(rango_minimo__lte=factor, rango_maximo__gte=factor)
            usuario_id_usuario = Usuario.objects.get(pk=request.POST.get('usuario_id_usuario'))

            obj = Calificacion.objects.create(
                monto=monto,
                factor=factor,
                periodo=periodo,
                instrumento=instru,
                estado='ACTIVO',
                usuario_id_usuario=usuario_id_usuario,
                factor_val_id_factor=fv
            )
            Auditoria.registrar(
                accion='CREAR',
                tabla='Calificacion',
                cambios=f'Nuevo registro id={obj.calid}, monto={monto}, factor={factor}, periodo={periodo}',
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Calificación creada correctamente.')
        except Exception as e:
            messages.error(request, f'Datos incorrectos: {e}')
    return _back_to_cal_list(request)

# ---------- CARGA MASIVA ----------
@login_required
def carga_masiva(request):
    if request.method == 'POST' and request.FILES.get('archivo'):
        try:
            archivo = request.FILES['archivo']
            data = json.load(archivo)
            obj = CargaMasiva.objects.create(archivo=data, errores='')
            Auditoria.registrar(
                accion='CARGA_MASIVA',
                tabla='CargaMasiva',
                cambios=f'Archivo id={obj.id_cm}',
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Archivo cargado y registrado.')
        except Exception as e:
            messages.error(request, f'Error en el archivo: {e}')
    return redirect(get_redirect_url(request))

# ---------- GUARDAR CALIFICACIÓN (con validación) ----------
@login_required
def guardar_calificacion(request):
    if request.method == 'POST':
        calid = request.POST.get('calid')
        if calid:
            return actualizar_calificacion(request, calid)

        try:
            monto   = float(request.POST.get('monto'))
            factor  = float(request.POST.get('factor'))
            periodo = datetime.datetime.strptime(request.POST.get('periodo'), '%Y-%m').date()

            errores = validar_calificacion(monto, factor, periodo)
            if errores:
                for e in errores:
                    messages.error(request, e)
                return _back_to_cal_list(request)

            instru = InstrumentoNI.objects.get(pk=request.POST.get('instrumento'))
            fv     = Factor_Val.objects.get(rango_minimo__lte=factor, rango_maximo__gte=factor)

            usuario_perfil = Usuario.objects.get(pk=request.POST.get('usuario_id_usuario'))
            usuario_auth   = usuario_perfil.user_auth

            obj = Calificacion.objects.create(
                monto=monto,
                factor=factor,
                periodo=periodo,
                instrumento=instru,
                estado='ACTIVO',
                usuario_id_usuario=usuario_auth,
                factor_val_id_factor=fv
            )
            Auditoria.registrar(
                accion='CREAR',
                tabla='Calificacion',
                cambios=f'Nuevo registro id={obj.calid}, monto={monto}, factor={factor}, periodo={periodo}',
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Calificación guardada.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
    return _back_to_cal_list(request)

# ---------- GUARDAR USUARIO ----------
@login_required
def guardar_usuario(request):
    if request.method == 'POST':
        id_usuario = request.POST.get('id_usuario')
        if id_usuario:
            return actualizar_usuario(request, id_usuario)

        try:
            nombre = request.POST.get('nombre')
            rut = request.POST.get('rut')
            email = request.POST.get('email')
            rol_id = request.POST.get('rol')

            # Validación para operadores: no pueden crear administradores ni operadores
            if request.user.perfil.rol_id.nombre_rol.lower() == 'operador':
                rol_obj = Rol.objects.get(pk=rol_id)
                if rol_obj.nombre_rol.lower() in ['administrador', 'operador']:
                    messages.error(request, 'No puedes crear otros operadores o administradores. Solo puedes crear usuarios con rol Cliente')
                    return _back_to_user_list(request)

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
            usuario.email = email
            usuario.set_rut(rut)
            usuario.save()

            Auditoria.registrar(
                accion='CREAR',
                tabla='Usuario',
                cambios=f'Nuevo usuario id={usuario.id_usuario}, nombre={nombre}, rol_id={rol_id}',
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Usuario creado correctamente.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
    return _back_to_user_list(request)

# ---------- GUARDAR INSTRUMENTO ----------
@login_required
def guardar_instrumento(request):
    if request.method == 'POST':
        id_instru = request.POST.get('id_instru')
        if id_instru:
            return actualizar_instrumento(request, id_instru)

        try:
            nombre = request.POST.get('nombre')
            regla_es = request.POST.get('regla_es')
            estado = request.POST.get('estado')
            obj = InstrumentoNI.objects.create(
                nombre=nombre,
                regla_es=regla_es,
                estado=estado
            )
            Auditoria.registrar(
                accion='CREAR',
                tabla='InstrumentoNI',
                cambios=f'Nuevo instrumento id={obj.id_instru}, nombre={nombre}, estado={estado}',
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Instrumento creado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
    return _back_to_instrument_list(request)

# ---------- GUARDAR ROL ----------
@login_required
def guardar_rol(request):
    if request.method == 'POST':
        id_rol = request.POST.get('id_rol')
        if id_rol:
            return actualizar_rol(request, id_rol)

        try:
            nombre = request.POST.get('nombre_rol')
            descripcion = request.POST.get('descripcion_rol')
            obj = Rol.objects.create(
                nombre_rol=nombre,
                descripcion_rol=descripcion
            )
            Auditoria.registrar(
                accion='CREAR',
                tabla='Rol',
                cambios=f'Nuevo rol id={obj.id_rol}, nombre={nombre}',
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Rol creado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
    return _back_to_rol_list(request)

# ---------- ELIMINAR ----------
@login_required
def eliminar_calificacion(request, calid):
    obj = get_object_or_404(Calificacion, calid=calid)
    Auditoria.registrar(
        accion='ELIMINAR',
        tabla='Calificacion',
        cambios=f'Eliminada calificación id={calid}, instrumento={obj.instrumento.nombre}, monto={obj.monto}',
        fecha=date.today(),
        ip=request.META.get('REMOTE_ADDR', ''),
        firma=f'user:{request.user.id}',
        usuario=request.user
    )
    obj.delete()
    messages.success(request, 'Calificación eliminada.')
    return redirect(get_redirect_url(request))

@login_required
def eliminar_usuario(request, id_usuario):
    obj = get_object_or_404(Usuario, id_usuario=id_usuario)
    Auditoria.registrar(
        accion='ELIMINAR',
        tabla='Usuario',
        cambios=f'Eliminado usuario id={id_usuario}, nombre={obj.nombre}, rut={obj.rut}',
        fecha=date.today(),
        ip=request.META.get('REMOTE_ADDR', ''),
        firma=f'user:{request.user.id}',
        usuario=request.user
    )
    obj.delete()
    messages.success(request, 'Usuario eliminado.')
    return redirect(get_redirect_url(request))

@login_required
def eliminar_instrumento(request, id_instru):
    obj = get_object_or_404(InstrumentoNI, id_instru=id_instru)
    Auditoria.registrar(
        accion='ELIMINAR',
        tabla='InstrumentoNI',
        cambios=f'Eliminado instrumento id={id_instru}, nombre={obj.nombre}',
        fecha=date.today(),
        ip=request.META.get('REMOTE_ADDR', ''),
        firma=f'user:{request.user.id}',
        usuario=request.user
    )
    obj.delete()
    messages.success(request, 'Instrumento eliminado.')
    return redirect(get_redirect_url(request))

@login_required
def eliminar_rol(request, id_rol):
    obj = get_object_or_404(Rol, id_rol=id_rol)
    Auditoria.registrar(
        accion='ELIMINAR',
        tabla='Rol',
        cambios=f'Eliminado rol id={id_rol}, nombre={obj.nombre_rol}',
        fecha=date.today(),
        ip=request.META.get('REMOTE_ADDR', ''),
        firma=f'user:{request.user.id}',
        usuario=request.user
    )
    obj.delete()
    messages.success(request, 'Rol eliminado.')
    return redirect(get_redirect_url(request))

@login_required
def eliminar_permiso(request, id_permiso):
    obj = get_object_or_404(Permiso, id_permiso=id_permiso)
    Auditoria.registrar(
        accion='ELIMINAR',
        tabla='Permiso',
        cambios=f'Eliminado permiso id={id_permiso}, nombre={obj.nombre}',
        fecha=date.today(),
        ip=request.META.get('REMOTE_ADDR', ''),
        firma=f'user:{request.user.id}',
        usuario=request.user
    )
    obj.delete()
    messages.success(request, 'Permiso eliminado correctamente.')
    return redirect(get_redirect_url(request))

# ---------- GUARDAR PERMISO ----------
@login_required
def guardar_permiso(request):
    if request.method == 'POST':
        try:
            pk = request.POST.get('id_permiso')
            nombre = request.POST.get('nombre')
            descripcion = request.POST.get('descripcion')
            if pk:
                Permiso.objects.filter(pk=pk).update(nombre=nombre, descripcion_permiso=descripcion)
                Auditoria.registrar(
                    accion='EDITAR',
                    tabla='Permiso',
                    cambios=f'Actualizado permiso id={pk}, nombre={nombre}',
                    fecha=date.today(),
                    ip=request.META.get('REMOTE_ADDR', ''),
                    firma=f'user:{request.user.id}',
                    usuario=request.user
                )
                messages.success(request, 'Permiso actualizado.')
            else:
                obj = Permiso.objects.create(nombre=nombre, descripcion_permiso=descripcion)
                Auditoria.registrar(
                    accion='CREAR',
                    tabla='Permiso',
                    cambios=f'Nuevo permiso id={obj.id_permiso}, nombre={nombre}',
                    fecha=date.today(),
                    ip=request.META.get('REMOTE_ADDR', ''),
                    firma=f'user:{request.user.id}',
                    usuario=request.user
                )
                messages.success(request, 'Permiso creado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
    return redirect(get_redirect_url(request))

# ---------- FILTRAR ----------
@login_required
def filtrar_calificaciones(request):
    rut = request.GET.get('rut')
    qs = Calificacion.objects.filter(
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

@login_required
def logout_usuario(request):
    logout(request)
    messages.success(request, 'Has cerrado sesión correctamente.')
    return redirect('login')

def principal(request):
    return render(request, 'principal.html')

# ---------- ACTUALIZAR CALIFICACIÓN (con validación) ----------
@login_required
def actualizar_calificacion(request, calid):
    cal = get_object_or_404(Calificacion, calid=calid)
    if request.method == 'POST':
        try:
            viejo = f"monto={cal.monto} factor={cal.factor} periodo={cal.periodo}"
            monto = float(request.POST.get('monto'))
            factor = float(request.POST.get('factor'))
            periodo = datetime.datetime.strptime(request.POST.get('periodo'), '%Y-%m').date()

            errores = validar_calificacion(monto, factor, periodo)
            if errores:
                for e in errores:
                    messages.error(request, e)
                return _back_to_cal_list(request)

            cal.monto = monto
            cal.factor = factor
            cal.periodo = periodo
            cal.instrumento = InstrumentoNI.objects.get(pk=request.POST.get('instrumento'))
            cal.factor_val_id_factor = Factor_Val.objects.get(
                rango_minimo__lte=factor,
                rango_maximo__gte=factor
            )
            cal.save()
            Auditoria.registrar(
                accion='EDITAR',
                tabla='Calificacion',
                cambios=f"Id={cal.calid} | Antes: {viejo}",
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Calificación actualizada correctamente.')
        except Exception as e:
            messages.error(request, f'Error al actualizar calificación: {e}')
        return _back_to_cal_list(request)
    return redirect(get_redirect_url(request))

# ---------- ACTUALIZAR USUARIO ----------
@login_required
def actualizar_usuario(request, id_usuario):
    usuario = get_object_or_404(Usuario, id_usuario=id_usuario)
    if request.method == 'POST':
        try:
            viejo = f"nombre={usuario.nombre} rut={usuario.rut} email={usuario.email} rol_id={usuario.rol_id_id}"
            usuario.nombre = request.POST.get('nombre')
            usuario.set_rut(request.POST.get('rut'))
            usuario.email = request.POST.get('email')
            usuario.rol_id_id = request.POST.get('rol')
            usuario.save()

            user_auth = usuario.user_auth
            user_auth.nombre = usuario.nombre
            user_auth.email = usuario.email
            user_auth.save()

            Auditoria.registrar(
                accion='EDITAR',
                tabla='Usuario',
                cambios=f"Id={id_usuario} | Antes: {viejo}",
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Usuario actualizado correctamente.')
        except Exception as e:
            messages.error(request, f'Error al actualizar usuario: {e}')
        return _back_to_user_list(request)
    return redirect(get_redirect_url(request))

# ---------- ACTUALIZAR INSTRUMENTO ----------
@login_required
def actualizar_instrumento(request, id_instru):
    instrumento = get_object_or_404(InstrumentoNI, id_instru=id_instru)
    if request.method == 'POST':
        try:
            viejo = f"nombre={instrumento.nombre} estado={instrumento.estado}"
            instrumento.nombre = request.POST.get('nombre')
            instrumento.regla_es = request.POST.get('regla_es')
            instrumento.estado = request.POST.get('estado')
            instrumento.save()
            Auditoria.registrar(
                accion='EDITAR',
                tabla='InstrumentoNI',
                cambios=f"Id={id_instru} | Antes: {viejo}",
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Instrumento actualizado correctamente.')
        except Exception as e:
            messages.error(request, f'Error al actualizar instrumento: {e}')
        return _back_to_instrument_list(request)
    return redirect(get_redirect_url(request))

# ---------- ACTUALIZAR ROL ----------
@login_required
def actualizar_rol(request, id_rol):
    rol = get_object_or_404(Rol, id_rol=id_rol)
    if request.method == 'POST':
        try:
            viejo = f"nombre={rol.nombre_rol} descripcion={rol.descripcion_rol}"
            rol.nombre_rol = request.POST.get('nombre_rol')
            rol.descripcion_rol = request.POST.get('descripcion_rol')
            rol.save()
            Auditoria.registrar(
                accion='EDITAR',
                tabla='Rol',
                cambios=f"Id={id_rol} | Antes: {viejo}",
                fecha=date.today(),
                ip=request.META.get('REMOTE_ADDR', ''),
                firma=f'user:{request.user.id}',
                usuario=request.user
            )
            messages.success(request, 'Rol actualizado correctamente.')
        except Exception as e:
            messages.error(request, f'Error al actualizar rol: {e}')
        return _back_to_rol_list(request)
    return redirect(get_redirect_url(request))