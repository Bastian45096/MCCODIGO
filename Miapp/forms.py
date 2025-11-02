from django import forms
from django.contrib.auth import get_user_model

User = get_user_model


class Login_U(forms.Form):

    nombre_usuario = forms.CharField(label ='Nombre usuario/Test', max_length=150)
    contraseña_usuario = forms.CharField(label='Contrasñea usuario/Test', widget=forms.PasswordInput)

class Registrar_U(forms.ModelForm):

    creacion_contraseña = forms.CharField(label='Crear contraseña', widget=forms.PasswordInput)
    confirmacion_contraseña = forms.CharField(label='Repita contraseña por favor/test', widget=forms.PasswordInput)


    class Meta:
        Model = User

        fields = ('nombre', 'email')