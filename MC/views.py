from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from Miapp.forms import LoginUsuarioForm
from Miapp.models import (UserAuth, Usuario, Calificacion, InstrumentoNI,
                          Factor_Val, CargaMasiva, Rol, Permiso, Auditoria, RolPermiso, Busqueda)
import logging
import re
import datetime
import json
from django.contrib.auth import logout
from datetime import date
from urllib.parse import urlencode
from MC.decorator import requiere_permiso_operador
logger = logging.getLogger(__name__)

def validar_calificacion(monto, factor, periodo):
    errores = []
    if monto <= 0:
        errores.append("El monto debe ser mayor a 0 (ejemplo: 500000).")
    if factor <= 0:
        errores.append("El factor debe ser mayor a 0 (ejemplo: 1.5).")
    if periodo > date.today():
        errores.append("La fecha del período no puede ser futura. Ejemplo válido: 2025-05.")
    return errores

def _back_to_cal_list(request):
    base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
    query = urlencode({'seccion': 'calificacion'})
    return redirect(f'/{base}/?{query}')

def _back_to_user_list(request):
    base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
    query = urlencode({'seccion': 'usuario'})
    return redirect(f'/{base}/?{query}')

def _back_to_instrument_list(request):
    base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
    query = urlencode({'seccion': 'instrumento'})
    return redirect(f'/{base}/?{query}')

def _back_to_rol_list(request):
    base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
    query = urlencode({'seccion': 'rol'})
    return redirect(f'/{base}/?{query}')

def login_usuario(request):
    if request.method == 'POST':
        form = LoginUsuarioForm(request.POST)
        if form.is_valid():
            usuario_input = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, username=usuario_input, password=password)
            if user is not None:
                login(request, user)

                Auditoria.registrar(
                    accion='LOGIN',
                    tabla='UserAuth',
                    cambios=f'Usuario {user.email} ha iniciado sesión',
                    request=request
                )

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
                Auditoria.registrar(
                    accion='LOGIN_FALLIDO',
                    tabla='UserAuth',
                    cambios=f'Intento fallido: {usuario_input}',
                    request=request
                )
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
    permisos_objs = Permiso.objects.all()
    factor_vals = Factor_Val.objects.all()

    seccion = request.GET.get('seccion')
    accion = request.GET.get('accion')
    obj_id = request.GET.get('obj_id')

    obj = None

    # ============================================================
    # Diccionario de permisos para el ROL del usuario logueado
    # ============================================================
    permisos_nombres = RolPermiso.objects.filter(
        rol=request.user.perfil.rol_id
    ).values_list('permiso__nombre', flat=True)

    permisos = {
        # calificacion
        'crear_calificacion':      'crear_calificacion'      in permisos_nombres,
        'editar_calificacion':     'editar_calificacion'     in permisos_nombres,
        'eliminar_calificacion':   'eliminar_calificacion'   in permisos_nombres,
        # usuario
        'crear_usuario':           'crear_usuario'           in permisos_nombres,
        'editar_usuario':          'editar_usuario'          in permisos_nombres,
        'eliminar_usuario':        'eliminar_usuario'        in permisos_nombres,
        # instrumento
        'crear_instrumento':       'crear_instrumento'       in permisos_nombres,
        'editar_instrumento':      'editar_instrumento'      in permisos_nombres,
        'eliminar_instrumento':    'eliminar_instrumento'    in permisos_nombres,
        # rol
        'crear_rol':               'crear_rol'               in permisos_nombres,
        'editar_rol':              'editar_rol'              in permisos_nombres,
        'eliminar_rol':            'eliminar_rol'            in permisos_nombres,
        # permiso
        'crear_permiso':           'crear_permiso'           in permisos_nombres,
        'editar_permiso':          'editar_permiso'          in permisos_nombres,
        'eliminar_permiso':        'eliminar_permiso'        in permisos_nombres,
        # factorval
        'crear_factorval':         'crear_factorval'         in permisos_nombres,
        'editar_factorval':        'editar_factorval'        in permisos_nombres,
        'eliminar_factorval':      'eliminar_factorval'      in permisos_nombres,
        # asignaciones
        'asignar_permisos':        'asignar_permisos'        in permisos_nombres,
        'editar_asignaciones':     'editar_asignaciones'     in permisos_nombres,
        'eliminar_asignaciones':   'eliminar_asignaciones'   in permisos_nombres,
        # extras
        'filtrar_calificaciones':  'filtrar_calificaciones'  in permisos_nombres,
        'carga_masiva':            'carga_masiva'            in permisos_nombres,
        'visualizar_usuarios':     'visualizar_usuarios'     in permisos_nombres,
    }

    # ===============  ASIGNACIONES  ===============
    if seccion == 'asignacion_permisos_editacion':
        asignaciones = RolPermiso.objects.select_related('rol', 'permiso').all()
        return render(request, 'inicioAdmin.html', {
            'instrumentos': instrumentos,
            'roles': roles,
            'usuarios': usuarios,
            'calificaciones': calificaciones,
            'permisos': permisos_objs,
            'factor_vals': factor_vals,
            'seccion': seccion,
            'accion': accion,
            'obj': obj,
            'obj_id': obj_id,
            'asignaciones': asignaciones,
            'permisos': permisos,               # ← pasamos el diccionario
        })

    # ===============  OBJETOS A EDITAR  ===============
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
    elif seccion == 'factorval' and accion == 'editar' and obj_id:
        obj = Factor_Val.objects.get(id_factor=obj_id)

    # ===============  CREAR  ===============
    elif seccion == 'usuario' and accion == 'crear':
        return render(request, 'inicioAdmin.html', {
            'instrumentos': instrumentos,
            'roles': roles,
            'usuarios': usuarios,
            'calificaciones': calificaciones,
            'permisos': permisos_objs,
            'factor_vals': factor_vals,
            'seccion': seccion,
            'accion': accion,
            'obj': obj,
            'obj_id': obj_id,
            'crear_usuario': True,
            'permisos': permisos,               # ← aquí también
        })
    elif seccion == 'instrumento' and accion == 'crear':
        return render(request, 'inicioAdmin.html', {
            'instrumentos': instrumentos,
            'roles': roles,
            'usuarios': usuarios,
            'calificaciones': calificaciones,
            'permisos': permisos_objs,
            'factor_vals': factor_vals,
            'seccion': seccion,
            'accion': accion,
            'obj': obj,
            'obj_id': obj_id,
            'crear_instrumento': True,
            'permisos': permisos,               # ← aquí también
        })
    elif seccion == 'rol' and accion == 'crear':
        return render(request, 'inicioAdmin.html', {
            'instrumentos': instrumentos,
            'roles': roles,
            'usuarios': usuarios,
            'calificaciones': calificaciones,
            'permisos': permisos_objs,
            'factor_vals': factor_vals,
            'seccion': seccion,
            'accion': accion,
            'obj': obj,
            'obj_id': obj_id,
            'crear_rol': True,
            'permisos': permisos,               # ← aquí también
        })
    elif seccion == 'rol' and accion == 'editar' and obj_id:
        return render(request, 'inicioAdmin.html', {
            'instrumentos': instrumentos,
            'roles': roles,
            'usuarios': usuarios,
            'calificaciones': calificaciones,
            'permisos': permisos_objs,
            'factor_vals': factor_vals,
            'seccion': seccion,
            'accion': accion,
            'obj': obj,
            'obj_id': obj_id,
            'editar_rol': True,
            'permisos': permisos,               # ← aquí también
        })

    # ===============  RETURN GENERAL  ===============
    return render(request, 'inicioAdmin.html', {
        'instrumentos': instrumentos,
        'roles': roles,
        'usuarios': usuarios,
        'calificaciones': calificaciones,
        'permisos': permisos_objs,
        'factor_vals': factor_vals,
        'seccion': seccion,
        'accion': accion,
        'obj': obj,
        'obj_id': obj_id,
        'permisos': permisos,                   # ← siempre va
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

    # ➜➜➜ Diccionario de permisos para el template
    permisos_nombres = RolPermiso.objects.filter(
        rol=request.user.perfil.rol_id
    ).values_list('permiso__nombre', flat=True)

    permisos = {
        'crear_calificacion':      'crear_calificacion'      in permisos_nombres,
        'editar_calificacion':     'editar_calificacion'     in permisos_nombres,
        'crear_usuario':           'crear_usuario'           in permisos_nombres,
        'editar_usuario':          'editar_usuario'          in permisos_nombres,
        'crear_instrumento':       'crear_instrumento'       in permisos_nombres,
        'editar_instrumento':      'editar_instrumento'      in permisos_nombres,
        'filtrar_calificaciones':  'filtrar_calificaciones'  in permisos_nombres,
        'carga_masiva':            'carga_masiva'            in permisos_nombres,
    }

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
        'permisos': permisos,
    })

@login_required
def inicio(request):
    perfil = None
    rol_nombre = "Cliente"
    nombre_usuario = request.user.nombre
    calificaciones = []
    mensaje = None

    # ========== Diccionario de permisos para cliente ==========
    permisos_nombres = RolPermiso.objects.filter(
        rol=request.user.perfil.rol_id
    ).values_list('permiso__nombre', flat=True)

    permisos = {
        'filtrar_propias_calificaciones': 'filtrar_propias_calificaciones' in permisos_nombres,
    }
    # ==========================================================

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
        'permisos': permisos,  # ← pasamos el diccionario
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

@login_required
@requiere_permiso_operador('crear_calificacion')
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
                request=request
            )
            messages.success(request, 'Calificación creada correctamente.')
        except Exception as e:
            messages.error(request, f'Datos incorrectos: {e}')
    return _back_to_cal_list(request)

@login_required
@requiere_permiso_operador('carga_masiva')
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
                request=request
            )
            messages.success(request, 'Archivo cargado y registrado.')
        except Exception as e:
            messages.error(request, f'Error en el archivo: {e}')
    return redirect(get_redirect_url(request))

@login_required
@requiere_permiso_operador('editar_calificacion')
def guardar_calificacion(request):
    if request.method == 'POST':
        calid = request.POST.get('calid')
        if calid:
            return actualizar_calificacion(request, calid)

        try:
            monto = float(request.POST.get('monto'))
            factor = float(request.POST.get('factor'))
            periodo = datetime.datetime.strptime(request.POST.get('periodo'), '%Y-%m').date()

            errores = validar_calificacion(monto, factor, periodo)
            if errores:
                for e in errores:
                    messages.error(request, e)
                return _back_to_cal_list(request)

            # 🔒 VALIDACIÓN NUEVA: factor debe estar dentro del rango del FactorVal
            try:
                fv = Factor_Val.objects.get(
                    rango_minimo__lte=factor,
                    rango_maximo__gte=factor
                )
            except Factor_Val.DoesNotExist:
                messages.error(
                    request,
                    f'El factor {factor} no está dentro del rango permitido por el FactorVal seleccionado.'
                )
                return _back_to_cal_list(request)

            instru = InstrumentoNI.objects.get(pk=request.POST.get('instrumento'))
            usuario_perfil = Usuario.objects.get(pk=request.POST.get('usuario_id_usuario'))
            usuario_auth = usuario_perfil.user_auth

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
                request=request
            )
            messages.success(request, 'Calificación guardada.')

        except Exception as e:
            messages.error(request, f'Error: {e}')
    return _back_to_cal_list(request)

@login_required
@requiere_permiso_operador('crear_usuario')
def guardar_usuario(request):
    if request.method == 'POST':
        id_usuario = request.POST.get('id_usuario')
        if id_usuario:
            return actualizar_usuario(request, id_usuario)

        try:
            nombre = request.POST.get('nombre')
            rut = request.POST.get('rut')
            email = request.POST.get('email')
            password = request.POST.get('password')
            rol_id = request.POST.get('rol')

            if not password:
                messages.error(request, 'Debes ingresar una contraseña.')
                return _back_to_user_list(request)

            if request.user.perfil.rol_id.nombre_rol.lower() == 'operador':
                rol_obj = Rol.objects.get(pk=rol_id)
                if rol_obj.nombre_rol.lower() in ['administrador', 'operador']:
                    messages.error(request, 'No puedes crear otros operadores o administradores. Solo puedes crear usuarios con rol Cliente')
                    return _back_to_user_list(request)

            try:
                validate_password(password)
            except ValidationError as e:
                messages.error(request, f'Contraseña inválida: {" ".join(e.messages)}')
                return _back_to_user_list(request)

            user = UserAuth.objects.create_user(
                nombre=nombre,
                email=email,
                password=password
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
                request=request
            )
            messages.success(request, 'Usuario creado correctamente.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
    return _back_to_user_list(request)

@login_required
@requiere_permiso_operador('crear_instrumento')
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
                request=request
            )
            messages.success(request, 'Instrumento creado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
    return _back_to_instrument_list(request)

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
                request=request
            )
            messages.success(request, 'Rol creado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
    return _back_to_rol_list(request)

@login_required
def eliminar_calificacion(request, calid):
    obj = get_object_or_404(Calificacion, calid=calid)
    Auditoria.registrar(
        accion='ELIMINAR',
        tabla='Calificacion',
        cambios=f'Eliminada calificación id={calid}, instrumento={obj.instrumento.nombre}, monto={obj.monto}',
        request=request
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
        request=request
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
        request=request
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
        request=request
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
        request=request
    )
    obj.delete()
    messages.success(request, 'Permiso eliminado correctamente.')
    return redirect(get_redirect_url(request))

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
                    request=request
                )
                messages.success(request, 'Permiso actualizado.')
            else:
                obj = Permiso.objects.create(nombre=nombre, descripcion_permiso=descripcion)
                Auditoria.registrar(
                    accion='CREAR',
                    tabla='Permiso',
                    cambios=f'Nuevo permiso id={obj.id_permiso}, nombre={nombre}',
                    request=request
                )
                messages.success(request, 'Permiso creado.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
    return redirect(get_redirect_url(request))

@login_required
@requiere_permiso_operador('filtrar_calificaciones')
def filtrar_calificaciones(request):

    # ---------- Recoger filtros ----------
    rut         = request.GET.get('rut', '').strip()
    fecha       = request.GET.get('fecha', '').strip()
    monto_min   = request.GET.get('monto_min', '').strip()
    monto_max   = request.GET.get('monto_max', '').strip()
    instrumento = request.GET.get('instrumento', '').strip()
    factor_val  = request.GET.get('factor_val', '').strip()

    # ---------- Guardar en tabla Busqueda ----------
    criterios = {
        'rut': rut,
        'fecha': fecha,
        'monto_min': monto_min,
        'monto_max': monto_max,
        'instrumento': instrumento,
        'factor_val': factor_val,
    }

    Busqueda.objects.create(
        criterios_busqueda=json.dumps(criterios, ensure_ascii=False),
        usuario_id_usuario=request.user,
        fecha_busqueda=datetime.now()  # ← guarda fecha y hora actual
    )

    # ---------- Guardar en Auditoria ----------
    Auditoria.registrar(
        accion='FILTRAR',
        tabla='Calificacion',
        cambios=f'Filtro aplicado por usuario {request.user.email}',
        request=request
    )

    # ---------- Query base ----------
    qs = Calificacion.objects.select_related('instrumento', 'factor_val_id_factor', 'usuario_id_usuario__perfil')

    try:
        perfil = request.user.perfil
        if perfil.rol_id.nombre_rol.lower() == 'cliente':
            qs = qs.filter(usuario_id_usuario=request.user)
    except Exception:
        pass

    errores = []

    if rut:
        clean = re.sub(r'[^0-9kK]', '', rut.upper())
        if len(clean) < 8 or len(clean) > 10:
            errores.append("RUT inválido.")
        else:
            qs = qs.filter(usuario_id_usuario__perfil__rut__icontains=clean)

    if fecha:
        try:
            fecha_parsed = datetime.strptime(fecha, '%Y-%m').date()
            qs = qs.filter(periodo=fecha_parsed)
        except ValueError:
            errores.append("Formato de fecha inválido. Use AAAA-MM.")

    if monto_min:
        try:
            qs = qs.filter(monto__gte=float(monto_min))
        except ValueError:
            errores.append("Monto mínimo debe ser un número válido.")

    if monto_max:
        try:
            qs = qs.filter(monto__lte=float(monto_max))
        except ValueError:
            errores.append("Monto máximo debe ser un número válido.")

    if instrumento:
        qs = qs.filter(instrumento__nombre__icontains=instrumento)

    if factor_val:
        try:
            qs = qs.filter(factor_val_id_factor__id_factor=int(factor_val))
        except ValueError:
            errores.append("Factor Val debe ser un número entero.")

    if errores:
        for e in errores:
            messages.error(request, e)
        base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
        return redirect(f'/{base}/?seccion=filtrar')

    return render(request, 'filtrar_resultado.html', {'calificaciones': qs})

@login_required
def visualizar_usuarios(request):
    operadores = Usuario.objects.filter(rol_id__nombre_rol__iexact='operador', activo='S')
    clientes = Usuario.objects.filter(rol_id__nombre_rol__iexact='cliente', activo='S')

    Auditoria.registrar(
        accion='VISUALIZAR',
        tabla='Usuario',
        cambios=f'Visualización de usuarios por {request.user.email}',
        request=request
    )

    return render(request, 'visualizar_usuarios.html', {
        'operadores': operadores,
        'clientes': clientes,
    })

@login_required
def logout_usuario(request):
    Auditoria.registrar(
        accion='LOGOUT',
        tabla='UserAuth',
        cambios=f'Usuario {request.user.email} ha cerrado sesión',
        request=request
    )
    logout(request)
    messages.success(request, 'Has cerrado sesión correctamente.')
    return redirect('login')

def principal(request):
    return render(request, 'principal.html')

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

            # 🔒 VALIDACIÓN NUEVA: factor debe estar dentro del rango del FactorVal
            try:
                fv = Factor_Val.objects.get(
                    rango_minimo__lte=factor,
                    rango_maximo__gte=factor
                )
            except Factor_Val.DoesNotExist:
                messages.error(
                    request,
                    f'El factor {factor} no está dentro del rango permitido por el FactorVal seleccionado.'
                )
                return _back_to_cal_list(request)

            cal.monto = monto
            cal.factor = factor
            cal.periodo = periodo
            cal.instrumento = InstrumentoNI.objects.get(pk=request.POST.get('instrumento'))
            cal.factor_val_id_factor = fv
            cal.save()

            Auditoria.registrar(
                accion='EDITAR',
                tabla='Calificacion',
                cambios=f"Id={cal.calid} | Antes: {viejo}",
                request=request
            )
            messages.success(request, 'Calificación actualizada correctamente.')

        except Exception as e:
            messages.error(request, f'Error al actualizar calificación: {e}')
        return _back_to_cal_list(request)
    return redirect(get_redirect_url(request))

@login_required
@requiere_permiso_operador('editar_usuario')
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

            new_password = request.POST.get('password')
            if new_password:
                try:
                    validate_password(new_password)
                    user_auth.set_password(new_password)
                    user_auth.save()
                    Auditoria.registrar(
                        accion='EDITAR',
                        tabla='Usuario',
                        cambios=f"Id={id_usuario} | Contraseña actualizada",
                        request=request
                    )
                except ValidationError as e:
                    messages.error(request, f'Contraseña inválida: {" ".join(e.messages)}')
                    return _back_to_user_list(request)

            Auditoria.registrar(
                accion='EDITAR',
                tabla='Usuario',
                cambios=f"Id={id_usuario} | Antes: {viejo}",
                request=request
            )
            messages.success(request, 'Usuario actualizado correctamente.')
        except Exception as e:
            messages.error(request, f'Error al actualizar usuario: {e}')
        return _back_to_user_list(request)
    return redirect(get_redirect_url(request))

@login_required
@requiere_permiso_operador('editar_instrumento')
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
                request=request
            )
            messages.success(request, 'Instrumento actualizado correctamente.')
        except Exception as e:
            messages.error(request, f'Error al actualizar instrumento: {e}')
        return _back_to_instrument_list(request)
    return redirect(get_redirect_url(request))

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
                request=request
            )
            messages.success(request, 'Rol actualizado correctamente.')
        except Exception as e:
            messages.error(request, f'Error al actualizar rol: {e}')
        return _back_to_rol_list(request)
    return redirect(get_redirect_url(request))

@login_required
def asignar_permisos(request):
    if request.method == 'POST':
        rol_id = request.POST.get('rol')
        permiso_id = request.POST.get('permiso')
        accion = request.POST.get('accion')

        rol = get_object_or_404(Rol, pk=rol_id)
        permiso = get_object_or_404(Permiso, pk=permiso_id)

        if accion == 'crear':
            if not RolPermiso.objects.filter(rol=rol, permiso=permiso).exists():
                RolPermiso.objects.create(rol=rol, permiso=permiso)
                Auditoria.registrar(
                    accion='CREAR',
                    tabla='RolPermiso',
                    cambios=f'Asignado permiso "{permiso.nombre}" al rol "{rol.nombre_rol}"',
                    request=request
                )
                messages.success(request, 'Asignación de permiso creada correctamente.')
            else:
                messages.error(request, 'Esta asignación ya existe.')
        elif accion == 'editar':
            asignacion = get_object_or_404(RolPermiso, rol=rol, permiso=permiso)
            asignacion.permiso = permiso
            asignacion.save()
            Auditoria.registrar(
                accion='EDITAR',
                tabla='RolPermiso',
                cambios=f'Editado permiso "{permiso.nombre}" para el rol "{rol.nombre_rol}"',
                request=request
            )
            messages.success(request, 'Asignación de permiso editada correctamente.')
        elif accion == 'eliminar':
            asignacion = get_object_or_404(RolPermiso, rol=rol, permiso=permiso)
            asignacion.delete()
            Auditoria.registrar(
                accion='ELIMINAR',
                tabla='RolPermiso',
                cambios=f'Eliminado permiso "{permiso.nombre}" del rol "{rol.nombre_rol}"',
                request=request
            )
            messages.success(request, 'Asignación de permiso eliminada correctamente.')
        else:
            messages.error(request, 'Acción no válida.')

    return redirect('/inicioAdmin/?seccion=asignacion_permisos')

@login_required
def asignar_permisos_editacion(request):
    if request.method == 'POST':
        asignacion_id = request.POST.get('asignacion_id')
        nueva_accion = request.POST.get('accion')

        asignacion = get_object_or_404(RolPermiso, pk=asignacion_id)

        if nueva_accion == 'eliminar':
            Auditoria.registrar(
                accion='ELIMINAR',
                tabla='RolPermiso',
                cambios=f'Eliminada asignación id={asignacion_id} (rol={asignacion.rol.nombre_rol}, permiso={asignacion.permiso.nombre})',
                request=request
            )
            asignacion.delete()
            messages.success(request, 'Asignación eliminada correctamente.')

        elif nueva_accion == 'editar':
            nuevo_rol_id = request.POST.get('nuevo_rol')
            nuevo_permiso_id = request.POST.get('nuevo_permiso')

            cambios = []
            if nuevo_rol_id and int(nuevo_rol_id) != asignacion.rol.id_rol:
                nuevo_rol = get_object_or_404(Rol, pk=nuevo_rol_id)
                cambios.append(f"rol:{asignacion.rol.nombre_rol}→{nuevo_rol.nombre_rol}")
                asignacion.rol = nuevo_rol

            if nuevo_permiso_id and int(nuevo_permiso_id) != asignacion.permiso.id_permiso:
                nuevo_permiso = get_object_or_404(Permiso, pk=nuevo_permiso_id)
                cambios.append(f"permiso:{asignacion.permiso.nombre}→{nuevo_permiso.nombre}")
                asignacion.permiso = nuevo_permiso

            if cambios:
                asignacion.save()
                Auditoria.registrar(
                    accion='EDITAR',
                    tabla='RolPermiso',
                    cambios=f"Id={asignacion_id} | {' | '.join(cambios)}",
                    request=request
                )
                messages.success(request, 'Asignación actualizada correctamente.')
            else:
                messages.info(request, 'No se realizaron cambios.')

        return redirect('/inicioAdmin/?seccion=asignacion_permisos_editacion')

    asignaciones = RolPermiso.objects.select_related('rol', 'permiso').all()
    roles = Rol.objects.all()
    permisos = Permiso.objects.all()
    base = 'inicioAdmin' if request.user.perfil.rol_id.nombre_rol.lower() == 'administrador' else 'inicioOperador'
    query = urlencode({'seccion': 'asignacion_permisos_editacion'})
    return redirect(f'/{base}/?{query}')



# ===== CREAR =====
@login_required
def crear_factorv(request):
    if request.method == 'POST':
        try:
            rango_minimo = float(request.POST.get('rango_minimo'))
            rango_maximo = float(request.POST.get('rango_maximo'))
            descripcion = request.POST.get('descripcion', '')  # Agregar esta línea
            
            if rango_maximo <= rango_minimo:
                messages.error(request, 'El rango máximo debe ser mayor que el mínimo.')
                return redirect('inicioAdmin')

            factor = Factor_Val.objects.create(
                rango_minimo=rango_minimo,
                rango_maximo=rango_maximo,
                descripcion=descripcion  # Agregar este parámetro
            )

            Auditoria.registrar(
                accion='CREAR',
                tabla='Factor_Val',
                cambios=f'Nuevo registro id={factor.id_factor}, rango_minimo={rango_minimo}, rango_maximo={rango_maximo}, descripcion={descripcion}',
                request=request
            )

            messages.success(request, 'FactorVal creado correctamente.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
        return redirect('inicioAdmin')
    return redirect('inicioAdmin')



# ===== LISTAR / SELECCIONAR PARA EDITAR =====
@login_required
def editar_factorv(request):
    factor_vals = Factor_Val.objects.all()
    obj = None
    obj_id = request.GET.get('obj_id')
    if obj_id:
        obj = get_object_or_404(Factor_Val, id_factor=obj_id)
    return render(request, 'inicioAdmin.html', {
        'seccion': 'factorval',
        'accion': 'editar',
        'factor_vals': factor_vals,
        'obj': obj,
        'obj_id': obj_id,
    })


# ===== ACTUALIZAR =====
@login_required
def actualizar_factorv(request, id_factor):
    factor = get_object_or_404(Factor_Val, id_factor=id_factor)
    if request.method == 'POST':
        try:
            viejo = f'rango_minimo={factor.rango_minimo}, rango_maximo={factor.rango_maximo}'
            rango_minimo = float(request.POST.get('rango_minimo'))
            rango_maximo = float(request.POST.get('rango_maximo'))
            if rango_maximo <= rango_minimo:
                messages.error(request, 'El rango máximo debe ser mayor que el mínimo.')
                return redirect('editar_factorv')

            factor.rango_minimo = rango_minimo
            factor.rango_maximo = rango_maximo
            factor.save()

            nuevo = f'rango_minimo={factor.rango_minimo}, rango_maximo={factor.rango_maximo}'
            Auditoria.registrar(
                accion='EDITAR',
                tabla='Factor_Val',
                cambios=f'Id={factor.id_factor} | Antes: {viejo} → Después: {nuevo}',
                request=request
            )

            messages.success(request, 'FactorVal actualizado correctamente.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
        return redirect('editar_factorv')
    return redirect('editar_factorv')


# ===== ELIMINAR =====
@login_required
def eliminar_factorv(request, id_factor):
    factor = get_object_or_404(Factor_Val, id_factor=id_factor)
    viejo = f'rango_minimo={factor.rango_minimo}, rango_maximo={factor.rango_maximo}'

    Auditoria.registrar(
        accion='ELIMINAR',
        tabla='Factor_Val',
        cambios=f'Id={factor.id_factor} | {viejo}',
        request=request
    )

    factor.delete()
    messages.success(request, 'FactorVal eliminado correctamente.')
    return redirect('editar_factorv')

from django.db import transaction

@login_required
def asignar_todos_permisos(request):
    """
    Asigna TODOS los permisos existentes al rol recibido.
    Si ya existía alguna asignación, la salta (no duplica).
    """
    if request.method != 'POST':
        return redirect('asignar_permisos')

    rol_id = request.POST.get('rol_id')
    if not rol_id:
        messages.error(request, 'Debes seleccionar un rol.')
        return redirect('asignar_permisos')

    rol = get_object_or_404(Rol, pk=rol_id)

    # Crear solo las que no existan
    with transaction.atomic():
        creadas = 0
        for p in Permiso.objects.all():
            obj, nuevo = RolPermiso.objects.get_or_create(rol=rol, permiso=p)
            if nuevo:
                creadas += 1

    Auditoria.registrar(
        accion='ASIGNAR_MASIVA',
        tabla='RolPermiso',
        cambios=f'Se asignaron {creadas} permisos nuevos al rol "{rol.nombre_rol}"',
        request=request
    )
    messages.success(request, f'Se asignaron {creadas} permisos al rol "{rol.nombre_rol}".')
    return redirect('asignar_permisos')


@login_required
def quitar_todos_permisos(request):
    """
    Elimina TODAS las asignaciones de un rol (útil para volver a empezar).
    """
    if request.method != 'POST':
        return redirect('asignar_permisos')

    rol_id = request.POST.get('rol_id')
    if not rol_id:
        messages.error(request, 'Debes seleccionar un rol.')
        return redirect('asignar_permisos')

    rol = get_object_or_404(Rol, pk=rol_id)
    borradas, _ = RolPermiso.objects.filter(rol=rol).delete()

    Auditoria.registrar(
        accion='QUITAR_MASIVA',
        tabla='RolPermiso',
        cambios=f'Se eliminaron {borradas} asignaciones del rol "{rol.nombre_rol}"',
        request=request
    )
    messages.success(request, f'Se eliminaron {borradas} asignaciones del rol "{rol.nombre_rol}".')
    return redirect('asignar_permisos')