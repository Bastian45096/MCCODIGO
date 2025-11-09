# tests.py
import json
import datetime
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from Miapp.models import (
    UserAuth, Rol, Permiso, RolPermiso,
    InstrumentoNI, Factor_Val, Calificacion,
    CargaMasiva, Busqueda, Auditoria
)

User = get_user_model()


# ----------------------------------------------------------
# 1) UserAuthManager -> create_user / create_superuser
# ----------------------------------------------------------
class UserAuthManagerTest(TestCase):
    def test_create_user(self):
        u = UserAuth.objects.create_user(nombre='Ana', email='ana@test.com', password='ana123')
        self.assertEqual(u.email, 'ana@test.com')
        self.assertTrue(u.check_password('ana123'))
        self.assertFalse(u.is_superuser)

    def test_create_superuser(self):
        s = UserAuth.objects.create_superuser(nombre='Admin', email='admin@test.com', password='admin123')
        self.assertTrue(s.is_staff)
        self.assertTrue(s.is_superuser)


# ----------------------------------------------------------
# 2) Rol -> Agregar_rol / Eliminar_rol / Actualizar_descripcion
# ----------------------------------------------------------
class RolTest(TestCase):
    def test_agregar_y_actualizar(self):
        rol = Rol(nombre_rol='Operador', descripcion_rol='Desc1')
        rol.Agregar_rol('Operador', 'Desc1')
        self.assertEqual(rol.nombre_rol, 'Operador')

        rol.Actualizar_descripcion('Nueva desc')
        rol.refresh_from_db()
        self.assertEqual(rol.descripcion_rol, 'Nueva desc')

    def test_eliminar_rol(self):
        rol = Rol.objects.create(nombre_rol='Temp', descripcion_rol='Temp')
        pk = rol.pk
        rol.Eliminar_rol()
        self.assertFalse(Rol.objects.filter(pk=pk).exists())


# ----------------------------------------------------------
# 3) Permiso -> Asignar_permisos_a_rol
# ----------------------------------------------------------
class PermisoTest(TestCase):
    def test_asignar_permisos(self):
        rol = Rol.objects.create(nombre_rol='Rol1', descripcion_rol='D1')
        p1 = Permiso.objects.create(nombre='Crear', descripcion_permiso='Crear datos')
        p2 = Permiso.objects.create(nombre='Editar', descripcion_permiso='Editar datos')

        p1.Asignar_permisos_a_rol(rol, [p1, p2])
        self.assertEqual(rol.permiso_set.count(), 2)


# ----------------------------------------------------------
# 4) InstrumentoNI -> Gestionar
# ----------------------------------------------------------
class InstrumentoNITest(TestCase):
    def test_gestionar(self):
        ins = InstrumentoNI.objects.create(nombre='INS1', regla_es='R1', estado='A')
        ins.Gestionar(nombre='INS2', estado='I')
        ins.refresh_from_db()
        self.assertEqual(ins.nombre, 'INS2')
        self.assertEqual(ins.estado, 'I')


# ----------------------------------------------------------
# 5) Factor_Val -> validar_factor
# ----------------------------------------------------------
class FactorValTest(TestCase):
    def test_factor_valido(self):
        f = Factor_Val(rango_minimo=1, rango_maximo=10)
        self.assertTrue(f.validar_factor())

    def test_factor_invalido(self):
        f = Factor_Val(rango_minimo=10, rango_maximo=1)
        with self.assertRaises(ValueError):
            f.validar_factor()


# ----------------------------------------------------------
# 6) Calificacion -> Crear_Calificacion / Editar_calificacion / Eliminar_calificacion
# ----------------------------------------------------------
class CalificacionTest(TestCase):
    def setUp(self):
        self.user = UserAuth.objects.create_user(nombre='U1', email='u1@test.com', password='u1')
        self.ins = InstrumentoNI.objects.create(nombre='INS1', regla_es='R1', estado='A')
        self.factor = Factor_Val.objects.create(rango_minimo=0, rango_maximo=10, descripcion='F1')

    def test_crear_calificacion(self):
        c = Calificacion.Crear_Calificacion(
            monto=1000, factor=1.5, periodo='2025-07-01',
            instrumento=self.ins, estado='OK', usuario=self.user, factor_val=self.factor
        )
        self.assertEqual(c.monto, 1000)
        self.assertEqual(Calificacion.objects.count(), 1)

    def test_editar_calificacion(self):
        c = Calificacion.objects.create(
            monto=1000, factor=1, periodo='2025-07-01',
            instrumento=self.ins, estado='PENDIENTE',
            usuario_id_usuario=self.user, factor_val_id_factor=self.factor,
            fecha_creacion='2025-07-01', fecha_modificacion='2025-07-01'
        )
        c.Editar_calificacion(monto=2000, estado='APROBADO')
        c.refresh_from_db()
        self.assertEqual(c.monto, 2000)
        self.assertEqual(c.estado, 'APROBADO')

    def test_eliminar_calificacion(self):
        c = Calificacion.objects.create(
            monto=1000, factor=1, periodo='2025-07-01',
            instrumento=self.ins, estado='PENDIENTE',
            usuario_id_usuario=self.user, factor_val_id_factor=self.factor,
            fecha_creacion='2025-07-01', fecha_modificacion='2025-07-01'
        )
        c.Eliminar_calificacion()
        self.assertEqual(Calificacion.objects.count(), 0)


# ----------------------------------------------------------
# 7) CargaMasiva -> cargar_desde_archivo / validar_archivo / _crear_calificaciones / generar_informe_errores
# ----------------------------------------------------------
class CargaMasivaTest(TestCase):
    def setUp(self):
        self.user = UserAuth.objects.create_user(nombre='U1', email='u1@test.com', password='u1')
        self.ins = InstrumentoNI.objects.create(nombre='INS1', regla_es='R1', estado='A')
        self.factor = Factor_Val.objects.create(rango_minimo=0, rango_maximo=10, descripcion='F1')

    def test_carga_ok(self):
        json_data = [{
            'monto': 1000,
            'instrumento_id': self.ins.id_instru,
            'factor_val_id': self.factor.id_factor,
            'periodo': '2025-07-01',
            'factor': 1.1,
            'estado': 'APROBADO'
        }]
        cm = CargaMasiva.cargar_desde_archivo(json_data, self.user.id)
        self.assertEqual(Calificacion.objects.count(), 1)
        self.assertEqual(cm.errores, '')

    def test_carga_con_error(self):
        json_data = [{'monto': 'xyz'}]  # dato inválido
        cm = CargaMasiva.cargar_desde_archivo(json_data, self.user.id)
        self.assertIn('Datos inválidos', cm.errores)

    def test_informe_errores(self):
        cm = CargaMasiva.objects.create(archivo=[], errores=json.dumps([{'fila': 1, 'error': 'E1'}]))
        informe = cm.generar_informe_errores()
        self.assertEqual(informe['status'], 'error')
        self.assertEqual(len(informe['errores']), 1)


# ----------------------------------------------------------
# 8) Busqueda -> Buscar
# ----------------------------------------------------------
class BusquedaTest(TestCase):
    def test_buscar(self):
        user = UserAuth.objects.create_user(nombre='U1', email='u1@test.com', password='u1')
        b1 = Busqueda.objects.create(criterios_busqueda='python django', usuario_id_usuario=user)
        b2 = Busqueda.objects.create(criterios_busqueda='java spring', usuario_id_usuario=user)

        resultado = Busqueda.Buscar('python')
        self.assertEqual(resultado.count(), 1)
        self.assertIn(b1, resultado)


# ----------------------------------------------------------
# 9) Auditoria -> Registrar
# ----------------------------------------------------------
class AuditoriaTest(TestCase):
    def test_registrar(self):
        user = UserAuth.objects.create_user(nombre='U1', email='u1@test.com', password='u1')
        a = Auditoria.Registrar(
            accion='INSERT', tabla='calificacion', cambios='{"monto": 1000}',
            fecha=datetime.date.today(), ip='127.0.0.1', firma='firma1', usuario=user
        )
        self.assertEqual(a.accion, 'INSERT')
        self.assertEqual(Auditoria.objects.count(), 1)
