from django import forms

class LoginUsuarioForm(forms.Form):
    email = forms.EmailField(label='Correo')
    password = forms.CharField(widget=forms.PasswordInput, label='Contraseña')
