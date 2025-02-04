from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ValidationError
from .models import CustomUser
import re
from django.contrib.auth import authenticate


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(label="Correo electrónico")
    control_number = forms.CharField(label="Número de control", max_length=10, min_length=10)
    password1 = forms.CharField(label="Contraseña", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirmar contraseña", widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ['email', 'name', 'surname', 'control_number', 'age', 'tel', 'password1', 'password2']

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()
        if not re.match(r'^[a-zA-Z0-9._%+-]+@utez\.edu\.mx$', email):
            raise forms.ValidationError("El correo debe ser del dominio @utez.edu.mx.")
        return email

    def clean_control_number(self):
        control_number = self.cleaned_data.get("control_number", "").strip()

        # Verificar longitud exacta de 10 caracteres
        if len(control_number) != 10:
            raise forms.ValidationError("El número de control debe tener exactamente 10 caracteres.")

        # Verificar que solo contenga números
        if not control_number.isdigit():
            raise forms.ValidationError("El número de control solo puede contener números.")

        return control_number

    def clean_password1(self):
        password = self.cleaned_data.get("password1", "").strip()
        if len(password) < 8:
            raise forms.ValidationError("La contraseña debe tener al menos 8 caracteres.")
        if not re.search(r'\d', password):
            raise forms.ValidationError("La contraseña debe contener al menos un número.")
        if not re.search(r'[!#$%&?]', password):
            raise forms.ValidationError("La contraseña debe contener al menos un símbolo (!, #, $, %, & o ?).")
        if not re.search(r'[A-Z]', password):
            raise forms.ValidationError("La contraseña debe contener al menos una letra mayúscula.")
        return password

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Las contraseñas no coinciden.")

        return cleaned_data


class CustomUserLoginForm(AuthenticationForm):
    username = forms.EmailField(label="Correo electrónico", max_length=150)  # Cambiamos email a username

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("username")  # Django espera "username"
        password = cleaned_data.get("password")

        if email and password:
            user = authenticate(username=email, password=password)
            if not user:
                raise forms.ValidationError("Usuario o contraseña incorrectos.")

        return cleaned_data