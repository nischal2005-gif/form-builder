from django import forms
from .models import *

class FieldForm(forms.ModelForm):
    class Meta:
        model = Field
        fields = ['label', 'field_type', 'required', 'choices', 'regex_validation', 'regex_error_message']
        widgets = {
            'regex_validation': forms.TextInput(attrs={'placeholder': '^[a-zA-Z ]+$'}),
            'regex_error_message': forms.TextInput(attrs={'placeholder': 'Custom error message'})
        }

class SMTPSettingsForm(forms.ModelForm):
    smtp_password = forms.CharField(widget=forms.PasswordInput())
    
    class Meta:
        model = SMTPSenderConfig
        fields = ['email', 'smtp_host', 'smtp_port', 'smtp_username', 'smtp_password']