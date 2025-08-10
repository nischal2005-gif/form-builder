from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
import re
import secrets
FIELD_TYPES = [
    ('text', 'Text'),
    ('email', 'Email'),
    ('textarea', 'Textarea'),
    ('number', 'Number'),
    ('date', 'Date'),
    ('radio', 'Radio'),
    ('checkbox', 'Checkbox'),
]

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractUser):
    username = None
    email = models.EmailField('email address', unique=True)
    is_verified = models.BooleanField(default=False)
    verification_token = models.UUIDField(default=uuid.uuid4, editable=False)
    token_created_at = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

class SMTPSenderConfig(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='smtp_configs',
        null=True,  # Make user optional
        blank=True
    )
    email = models.EmailField()
    smtp_host = models.CharField(max_length=255)
    smtp_port = models.IntegerField()
    smtp_username = models.CharField(max_length=255)
    smtp_password_encrypted = models.TextField()
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('email', 'smtp_host', 'smtp_username', 'smtp_password_encrypted')

class Form(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    api_key = models.CharField(max_length=64, unique=True, blank=True,null=True)
    smtp_config = models.ForeignKey(
        SMTPSenderConfig,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='forms',
        help_text="SMTP configuration for sending emails"
    )
    receiver_emails = models.TextField(
        help_text="Comma-separated list of email addresses for form submissions",
        blank=True
    )
    receiver_email = models.EmailField(
        help_text="(Legacy) Single receiver email",
        blank=True
    )
    recaptcha_enabled = models.BooleanField(default=False)
    email_confirmation_required = models.BooleanField(default=False)
    confirmation_message = models.TextField(
        blank=True, null=True,
        help_text="Template for the email confirmation message sent to the user"
    )
    email_message = models.TextField(
        blank=True, null=True,
        help_text="Template for the email message sent to receiver"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # Changed from CustomUser
        on_delete=models.CASCADE,
        related_name='forms',
        null=True,
        blank=True
    )

    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = secrets.token_urlsafe(48)  # 64-character key
        super().save(*args, **kwargs)

    def get_receiver_emails(self):
        if self.receiver_emails:
            return [email.strip() for email in self.receiver_emails.split(',') if email.strip()]
        elif self.receiver_email:
            return [self.receiver_email]
        return []

class Notification(models.Model):
    included_fields = models.TextField(
        blank=True,
        help_text="Comma-separated list of field names to include in emails (e.g. 'message,present_situation')"
    )
    confirmation_included_fields = models.TextField(
        blank=True, 
        help_text="Comma-separated list of field names for confirmation emails"
    )
    form = models.ForeignKey(Form, related_name='notifications', on_delete=models.CASCADE)
    smtp_config = models.ForeignKey(
        SMTPSenderConfig,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='notifications',
        help_text="SMTP configuration for sending this notification"
    )
    receiver_email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    is_confirmation = models.BooleanField(default=False)
    confirmation_subject = models.CharField(max_length=200, blank=True)
    confirmation_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    dynamic_receiver = models.BooleanField(default=False,
    help_text="Process placeholders in receiver email")
    
    def clean(self):
          if self.dynamic_receiver:
            if not re.search(r'\[[^\]]+\]', self.receiver_email):
                raise ValidationError(
                    "Dynamic receiver requires placeholders like [field_name] in email address"
                )
            else:
              if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', self.receiver_email):
                raise ValidationError("Invalid email address format")
    
    @property
    def sender_email(self):
        """Backward-compatible property"""
        return self.smtp_config.email if self.smtp_config else None
        
    def __str__(self):
        return f"Notification to {self.receiver_email} for {self.form.title}"

class Field(models.Model):
    form = models.ForeignKey(Form, related_name='fields', on_delete=models.CASCADE)
    name = models.CharField(max_length=255, default="default_field_name")
    label = models.CharField(max_length=255)
    field_type = models.CharField(max_length=20, choices=FIELD_TYPES)
    required = models.BooleanField(default=True)
    choices = models.TextField(blank=True)
    regex_validation = models.CharField(
        max_length=255, 
        blank=True,
        help_text="Enter a regex pattern for validation"
    )
    regex_error_message = models.CharField(
        max_length=255,
        blank=True,
        default="Invalid format"
    )
    order = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.label

class Submission(models.Model):
    form = models.ForeignKey(Form, related_name='submissions', on_delete=models.CASCADE)
    user_email = models.EmailField(blank=True, null=True)
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Submission to {self.form.title} on {self.submitted_at.strftime('%Y-%m-%d %H:%M')}"

class FieldResponse(models.Model):
    submission = models.ForeignKey(Submission, related_name='responses', on_delete=models.CASCADE)
    field = models.ForeignKey(Field, on_delete=models.CASCADE)
    response = models.TextField(blank=True)

    def __str__(self):
        return f"{self.field.label}: {self.response}"