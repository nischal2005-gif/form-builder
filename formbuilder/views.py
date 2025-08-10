from django.shortcuts import render, get_object_or_404, redirect
from django.core.mail import send_mail
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from cryptography.fernet import Fernet
from django.conf import settings
import requests
from django.contrib.auth.decorators import login_required
import smtplib
from email.mime.text import MIMEText
from .forms import FieldForm, SMTPSettingsForm
from django.forms import modelformset_factory
from email.utils import formatdate, make_msgid
from django.db import IntegrityError
import re
from django.contrib import messages
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from .models import *
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from .utilis import generate_token
from django.utils.encoding import force_bytes,force_str
from django.views.generic import View
from django.core.mail import EmailMessage
from django.http import HttpResponseForbidden
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import CustomUser 
import logging
from django.views.decorators.csrf import csrf_exempt


# Initialize Fernet once
fernet = Fernet(settings.FERNET_KEY.encode())
logger = logging.getLogger(__name__)

def encrypt(text):
    return fernet.encrypt(text.encode()).decode()

def decrypt(token):
    return fernet.decrypt(token.encode()).decode()

def clean_subject(subject):
    """Ensure subject line is safe for email headers"""
    subject = ' '.join(str(subject).split())  # Remove all newlines and extra spaces
    return subject[:998]  # RFC 2822 limit
def replace_placeholders(text, form_data, fields, is_subject=False):
    if not text:
        return ""

    # Find all email-type fields and their normalized names
    email_fields = {
        field.label.lower().replace(' ', '_'): form_data.get(field.label, "")
        for field in fields
        if field.field_type == 'email'
    }

    # Special case: [email] matches any email field
    if '[email]' in text.lower():
        # Use first non-empty email field found
        email_value = next((v for v in email_fields.values() if v), "")
        text = text.replace('[email]', email_value)

    # Replace all other placeholders (both email and regular fields)
    for field in fields:
        # Create normalized placeholder ([email_address], [contact_email] etc.)
        placeholder = f'[{field.label.lower().replace(" ", "_")}]'
        
        if placeholder in text.lower():  # Case-insensitive match
            value = form_data.get(field.label, "")
            if field.field_type == 'checkbox' and isinstance(value, list):
                value = ', '.join(value)
            text = text.replace(placeholder, str(value))

    if is_subject:
        text = clean_subject(text)

    return text

@login_required
def dashboard(request):
    user_forms = Form.objects.filter(user=request.user)
    user_submissions = Submission.objects.filter(form__user=request.user)
    user_notifications = Notification.objects.filter(form__user=request.user)
    
    num_forms = user_forms.count()
    num_submissions = user_submissions.count()
    num_emails = user_notifications.count()
    
    recent_submissions = user_submissions.order_by('-submitted_at')[:5]
    
    return render(request, 'dashboard.html', {
        'num_forms': num_forms,
        'num_submissions': num_submissions,
        'num_emails': num_emails,
        'recent_submissions': recent_submissions,
        'recent_activity_count': recent_submissions.count(),
        'confirmation_emails_count': user_notifications.filter(is_confirmation=True).count(),
        'notification_emails_count': user_notifications.filter(is_confirmation=False).count(),
    })
import json
@csrf_exempt
@login_required
def form_view(request, form_id):
    if not request.user.is_authenticated:
        return HttpResponseForbidden("You don't have permission")
    
    form_obj = get_object_or_404(Form, id=form_id)
    fields = form_obj.fields.all().order_by('order')

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type=='application/json':
        try:
            data=json.loads(request.body)

            api_key=None
            for header, value in request.headers.items():
                if header.lower()=='x-api-key':
                    api_key=value
                    break
            if not api_key:
                return JsonResponse({
                    'error':'API key required',
                    'status':401
                },status=401)
            
            if api_key !=form_obj.api_key:
                return JsonResponse({
                    'error':'Invalid API Key',
                    'status':403
                },status=403)
            request.POST=request.POST.copy()
            for key,value in data.items():
                request.POST[key]=value
        except json.JSONDecodeError:
            return JsonResponse({'error':'Invalid Json'},status=400)
        
        request.POST=request.POST.copy()
        for key, value in data.items():
            request.POST[key]= value

    # Prepare choice fields
    for field in fields:
        if field.field_type in ['radio', 'checkbox'] and field.choices:
            field.choices_list = [choice.strip() for choice in field.choices.split(',')]

    if request.method == 'POST':
        email_errors = []

        # reCAPTCHA validation
        if form_obj.recaptcha_enabled:
            recaptcha_response = request.POST.get('g-recaptcha-response')
            if not recaptcha_response:
                return render(request, 'form_view.html', {
                    'form_obj': form_obj,
                    'fields': fields,
                    'error': 'Please complete the CAPTCHA verification.',
                })
            
            recaptcha_secret = getattr(settings, 'RECAPTCHA_SECRET_KEY', None)
            if not recaptcha_secret:
                return render(request, 'form_view.html', {
                    'form_obj': form_obj,
                    'fields': fields,
                    'error': 'reCAPTCHA configuration error.',
                })

            verification_url = 'https://www.google.com/recaptcha/api/siteverify'
            data = {'secret': recaptcha_secret, 'response': recaptcha_response}
            result = requests.post(verification_url, data=data).json()

            if not result.get('success'):
                return render(request, 'form_view.html', {
                    'form_obj': form_obj,
                    'fields': fields,
                    'error': 'CAPTCHA verification failed. Please try again.',
                })

        # Process form submission
        user_email = request.POST.get("user_email", "")
        submission = Submission.objects.create(form=form_obj, user_email=user_email)
        form_data = {}
        field_errors = {}

        for field in fields:
            if field.field_type == 'checkbox':
                values = request.POST.getlist(field.label)
                response = ', '.join(values) if values else ''
            else:
                response = request.POST.get(field.label, "")
            
            if field.required and not response:
                field_errors[field.label] = "This field is required"
                continue
                
            if field.regex_validation and response:
                try:
                    if not re.fullmatch(field.regex_validation, response):
                        field_errors[field.label] = field.regex_error_message or f"Invalid format for {field.label}"
                        continue
                except re.error:
                    pass
            
            FieldResponse.objects.create(
                submission=submission,
                field=field,
                response=response
            )
            form_data[field.label] = response

        if field_errors:
            return render(request, 'form_view.html', {
                'form_obj': form_obj,
                'fields': fields,
                'field_errors': field_errors,
                'error': 'Please correct the errors below.',
            })

        # Enhanced email sending logic
        notifications = Notification.objects.filter(form=form_obj, is_confirmation=False)
        for notification in notifications:
            try:
                smtp_config = (
                    notification.smtp_config or
                    form_obj.smtp_config or
                    SMTPSenderConfig.objects.filter(is_verified=True).first()
                )

                if not smtp_config:
                    email_errors.append(f"No SMTP configuration found for notification to {notification.receiver_email}")
                    continue

                # Process recipient email with flexible placeholder handling
                recipient_email = notification.receiver_email
                
                if '[' in recipient_email and ']' in recipient_email:
                    placeholder=recipient_email.strip('[]').lower().replace(' ', '_')

                    if placeholder=='email':
                        recipient_email=next(
                              (v for v in form_data.values()
                               if isinstance(v, str) and '@' in v and '.' in v.split('@')[-1]),
                        )
                    else:
                        matching_fields=[
                            field for field in fields
                            if field.label.lower().replace(' ', '_') == placeholder 
                            and field.field_type == 'email'
                        ]
                        if matching_fields:
                            recipient_email=form_data.get(matching_fields[0].label, "")
                        else:
                            recipient_email=form_data.get(placeholder.replace('_',''),"")
                    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', recipient_email):
                        available_emails = [
                                        f"[{field.label.lower().replace(' ', '_')}]" 
                                        for field in fields
                                        if field.field_type == 'email'
                        ]
                        email_errors.append(
                                        f"Invalid email address from {notification.receiver_email}. "
                                        f"Available email fields: {', '.join(available_emails) or 'None'}"
                        )
                        continue


                  
                # Get included fields
                included_fields = fields
                if notification.included_fields:
                    included_names = [name.strip().lower().replace(' ', '_') for name in notification.included_fields.split(',')]
                    included_fields = [
                        field for field in fields 
                        if field.name.lower().replace(' ', '_') in included_names or 
                           field.label.lower().replace(' ', '_') in included_names
                    ]
                
                # Process subject and message with improved placeholder replacement
                subject = clean_subject(
                    replace_placeholders(
                        notification.subject or "New submission for [form_title]",
                        form_data,
                        included_fields,
                        is_subject=True
                    )
                )
                
                message = replace_placeholders(
                    notification.message or "You have received a new submission",
                    form_data,
                    included_fields
                )

                # Create and send email
                msg = MIMEText(message, 'plain', 'utf-8')
                msg["Subject"] = subject
                msg["From"] = smtp_config.email
                msg["To"] = recipient_email
                msg["Date"] = formatdate(localtime=True)
                
                with smtplib.SMTP(smtp_config.smtp_host, smtp_config.smtp_port) as server:
                    server.starttls()
                    server.login(smtp_config.smtp_username, decrypt(smtp_config.smtp_password_encrypted))
                    server.sendmail(smtp_config.email, [recipient_email], msg.as_string())

            except smtplib.SMTPException as e:
                error_msg = f"SMTP error sending to {recipient_email}: {str(e)}"
                logger.error(error_msg)
                email_errors.append(error_msg)
            except Exception as e:
                error_msg = f"Failed to send to {recipient_email}: {str(e)}"
                logger.error(error_msg, exc_info=True)
                email_errors.append(error_msg)

        if email_errors:
            return render(request, 'form_view.html', {
                'form_obj': form_obj,
                'fields': fields,
                'warning': "Form submitted, but some emails failed: " + ", ".join(email_errors),
            })

        return render(request, 'form_view.html', {
            'form_obj': form_obj,
            'fields': fields,
            'success': "Thank you for your submission!",
        })

    recaptcha_site_key = getattr(settings, 'RECAPTCHA_SITE_KEY', None) if form_obj.recaptcha_enabled else None
    
    return render(request, 'form_view.html', {
        'form_obj': form_obj,
        'fields': fields,
        'recaptcha_site_key': recaptcha_site_key,
        'smtp_configs': SMTPSenderConfig.objects.filter(is_verified=True)
    })

@login_required
def api_docs(request, form_id):
    form = get_object_or_404(Form, id=form_id, user=request.user)
    fields = form.fields.all()
    
    return render(request, 'api_docs.html', {
        'form': form,
        'fields': fields,
        'example_data': {f.label: "value" for f in fields}
    })

@csrf_exempt
@login_required
def create_form(request):
    FieldFormSet = modelformset_factory(Field, form=FieldForm, extra=1, can_delete=True)
    
    if request.method == 'POST':
        form_data = request.POST.copy()
        
        # Validate required fields
        if not form_data.get('title'):
            return render(request, 'form.html', {
                'error': 'Form title is required',
                'field_formset': FieldFormSet(form_data),
                'smtp_configs': SMTPSenderConfig.objects.filter(is_verified=True)
            })

        try:
            # Create form with current user as owner
            form_obj = Form.objects.create(
                title=form_data.get('title'),
                description=form_data.get('description', ''),
                # sender_email=form_data.get('sender_email', ''),
                receiver_emails=form_data.get('receiver_emails', ''),
                recaptcha_enabled='recaptcha_enabled' in form_data,
                email_confirmation_required='email_confirmation_required' in form_data,
                email_message=form_data.get('email_message', ''),
                confirmation_message=form_data.get('confirmation_message', ''),
                user=request.user  # Set the current user as owner
            )

            field_formset = FieldFormSet(form_data, queryset=Field.objects.none())
            if field_formset.is_valid():
                for field_form in field_formset:
                    if field_form.cleaned_data and not field_form.cleaned_data.get('DELETE', False):
                        field = field_form.save(commit=False)
                        field.form = form_obj
                        field.save()
            else:
                form_obj.delete()
                return render(request, 'form.html', {
                    'error': 'Invalid field data',
                    'field_formset': field_formset,
                    'smtp_configs': SMTPSenderConfig.objects.filter(is_verified=True)
                })

            messages.success(request, "Form created successfully!")
            return redirect('edit_form', form_id=form_obj.id)

        except IntegrityError as e:
            return render(request, 'form.html', {
                'error': f"Database error: {str(e)}",
                'field_formset': FieldFormSet(form_data),
                'smtp_configs': SMTPSenderConfig.objects.filter(is_verified=True)
            })

    return render(request, 'form.html', {
        'field_formset': FieldFormSet(queryset=Field.objects.none()),
        'form_obj': Form(),
        'smtp_configs': SMTPSenderConfig.objects.filter(is_verified=True)
    })

def edit_form(request, form_id):
    form_obj = get_object_or_404(Form, id=form_id)
    FieldFormSet = modelformset_factory(Field, form=FieldForm, extra=1, can_delete=True)

    if request.method == 'POST':
        form_data = request.POST.copy()
        form_obj.title = form_data.get('title')
        form_obj.description = form_data.get('description')
        form_obj.sender_email = form_data.get('sender_email')
        
        receiver_emails = form_data.get('receiver_emails', '')
        if receiver_emails:
            form_obj.receiver_emails = receiver_emails
            emails = [e.strip() for e in receiver_emails.split(',') if e.strip()]
            if emails:
                form_obj.receiver_email = emails[0]
        else:
            form_obj.receiver_email = form_data.get('receiver_email', '')
            form_obj.receiver_emails = form_obj.receiver_email

        form_obj.recaptcha_enabled = 'recaptcha_enabled' in form_data
        form_obj.email_confirmation_required = 'email_confirmation_required' in form_data
        form_obj.email_message = form_data.get('email_message')
        form_obj.confirmation_message = form_data.get('confirmation_message')
        
        try:
            form_obj.save()
        except IntegrityError as e:
            return render(request, 'form.html', {
                'form_obj': form_obj,
                'field_formset': FieldFormSet(queryset=form_obj.fields.all()),
                'error': f"Database error: {str(e)}",
                'smtp_configs': SMTPSenderConfig.objects.filter( is_verified=True)
            })

        field_formset = FieldFormSet(form_data, queryset=form_obj.fields.all())
        
        if field_formset.is_valid():
            instances = field_formset.save(commit=False)
            for instance in instances:
                instance.form = form_obj
                instance.save()
            
            for obj in field_formset.deleted_objects:
                obj.delete()
            
            messages.success(request, "Form updated successfully")
            return redirect('edit_form', form_id=form_obj.id)
        else:
            return render(request, 'form.html', {
                'form_obj': form_obj,
                'field_formset': field_formset,
                'error': "Please correct the errors below",
                'smtp_configs': SMTPSenderConfig.objects.filter(is_verified=True)
            })

    return render(request, 'form.html', {
        'form_obj': form_obj,
        'field_formset': FieldFormSet(queryset=form_obj.fields.all()),
        'smtp_configs': SMTPSenderConfig.objects.filter(is_verified=True)
    })
def home(request):
    if not request.user.is_authenticated:
        return redirect('handlelogin')
    
    forms = Form.objects.filter(user=request.user)  # Only show current user's forms
    return render(request, 'home.html', {'forms': forms})

@login_required
def verify_smtp_sender(request):
    if request.method == 'GET':
        email = request.GET.get("email", "")
        return render(request, "verify_smtp.html", {
            "email": email,
            "smtp_configs": SMTPSenderConfig.objects.filter(is_verified=True)  # Only show current user's configs
        })

    elif request.method == 'POST':
        try:
            email = request.POST.get("email")
            smtp_host = request.POST.get("smtp_host")
            smtp_port = int(request.POST.get("smtp_port"))
            smtp_username = request.POST.get("smtp_username")
            smtp_password = request.POST.get("smtp_password")

            # Validate inputs
            if not all([email, smtp_host, smtp_port, smtp_username, smtp_password]):
                return render(request, "verify_smtp.html", {
                    "error": "All fields are required",
                    "email": email,
                    "smtp_configs": SMTPSenderConfig.objects.filter(is_verified=True)
                })

            # Verify SMTP credentials
            msg = MIMEText("SMTP verification successful.")
            msg["Subject"] = "Verify SMTP"
            msg["From"] = email
            msg["To"] = email

            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.sendmail(email, [email], msg.as_string())

            # Save to DB - ensure user is set
            SMTPSenderConfig.objects.update_or_create(
                email=email,
                user=request.user,  # Include user in lookup
                defaults={
                    "smtp_host": smtp_host,
                    "smtp_port": smtp_port,
                    "smtp_username": smtp_username,
                    "smtp_password_encrypted": encrypt(smtp_password),
                    "is_verified": True,
                },
            )

            return render(request, "verify_smtp.html", {
                "success": "SMTP verified and saved", 
                "email": email,
                "smtp_configs": SMTPSenderConfig.objects.filter(user=request.user)
            })

        except smtplib.SMTPAuthenticationError:
            return render(request, "verify_smtp.html", {
                "error": "SMTP authentication failed", 
                "email": email,
                "smtp_configs": SMTPSenderConfig.objects.filter(user=request.user)
            })
        except Exception as e:
            return render(request, "verify_smtp.html", {
                "error": f"Error: {str(e)}", 
                "email": email,
                "smtp_configs": SMTPSenderConfig.objects.filter(user=request.user)
            })

    return JsonResponse({'error': 'Method not allowed'}, status=405)

def delete_form(request, form_id):
    form_obj = get_object_or_404(Form, id=form_id)
    if request.method == 'POST':
        form_obj.delete()
        messages.success(request, "Form deleted successfully")
        return redirect('home')
    return render(request, 'form_view.html', {
        'form_obj': form_obj,
        'error': 'Invalid request method',
    })

def manage_notifications(request, form_id):
    form = get_object_or_404(Form, id=form_id)
    notifications = Notification.objects.filter(form=form, is_confirmation=False)
    
    # Get the first verified SMTP config for the user
    smtp_config = SMTPSenderConfig.objects.filter(
        is_verified=True
    ).first()
    
    confirmation_notification = Notification.objects.filter(
        form=form, 
        is_confirmation=True
    ).first()
    
    if not confirmation_notification:
        confirmation_notification = Notification.objects.create(
            form=form,
            smtp_config=smtp_config,  # Use the SMTP config instead of sender_email
            receiver_email="",
            subject="",
            message="",
            is_confirmation=True,
            confirmation_subject="Your submission confirmation",
            confirmation_message="Thank you for your submission [user_email]!"
        )
    
    return render(request, 'notifications.html', {
        'form': form,
        'notifications': notifications,
        'confirmation_notification': confirmation_notification,
        'smtp_configs': SMTPSenderConfig.objects.filter(is_verified=True)
    })

def update_confirmation(request, form_id):
    if request.method == 'POST':
        form = get_object_or_404(Form, id=form_id)
        confirmation_notification = Notification.objects.filter(form=form, is_confirmation=True).first()
        
        if not confirmation_notification:
            confirmation_notification = Notification(
                form=form,
                is_confirmation=True
            )
        
        confirmation_notification.confirmation_subject = request.POST.get('confirmation_subject', '')
        confirmation_notification.confirmation_message = request.POST.get('confirmation_message', '')
        confirmation_notification.save()
        
        messages.success(request, "Confirmation settings updated")
        return redirect('manage_notifications', form_id=form.id)
    
    return redirect('home')

@csrf_exempt
def add_notification(request, form_id):
    form = get_object_or_404(Form, id=form_id)
    
    if request.method == 'POST':
        smtp_config_id = request.POST.get('smtp_config')
        
        try:
            smtp_config = SMTPSenderConfig.objects.get(id=smtp_config_id)
        except SMTPSenderConfig.DoesNotExist:
            messages.error(request, "Invalid SMTP configuration selected")
            return redirect('manage_notifications', form_id=form.id)
        
        # Create notification
        Notification.objects.create(
            form=form,
            smtp_config=smtp_config,
            receiver_email=request.POST.get('receiver_email'),
            subject=request.POST.get('subject'),
            message=request.POST.get('message'),
            dynamic_receiver='[' in request.POST.get('receiver_email', '') and ']' in request.POST.get('receiver_email', ''),
            is_confirmation=False
        )
        
        messages.success(request, "Notification added successfully")
        return redirect('manage_notifications', form_id=form.id)
    
    return render(request, 'add_notification.html', {
        'form': form,
        'smtp_configs': SMTPSenderConfig.objects.filter(is_verified=True)
    })
def delete_notification(request, notification_id):
    notification = get_object_or_404(Notification, id=notification_id)
    form_id = notification.form.id
    notification.delete()
    messages.success(request, 'Notification deleted successfully')
    return redirect('manage_notifications', form_id=form_id)

class SMTPSettingsListView(LoginRequiredMixin, ListView):
    model = SMTPSenderConfig
    template_name = 'smtp_settings_list.html'
    context_object_name = 'smtp_configs'
    
    def get_queryset(self):
        """Only show current user's SMTP configurations"""
        return SMTPSenderConfig.objects.filter(user=self.request.user)


class SMTPSettingsCreateView(CreateView):
    model = SMTPSenderConfig
    form_class = SMTPSettingsForm
    template_name = 'smtp_settings_form.html'
    success_url = reverse_lazy('smtp_settings_list')

    def form_valid(self, form):
        form.instance.smtp_password_encrypted = encrypt(form.cleaned_data['smtp_password'])
        return super().form_valid(form)

class SMTPSettingsUpdateView(UpdateView):
    model = SMTPSenderConfig
    form_class = SMTPSettingsForm
    template_name = 'smtp_settings_form.html'
    success_url = reverse_lazy('smtp_settings_list')

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        if self.object:
            kwargs['initial']['smtp_password'] = decrypt(self.object.smtp_password_encrypted)
        return kwargs

    def form_valid(self, form):
        form.instance.smtp_password_encrypted = encrypt(form.cleaned_data['smtp_password'])
        return super().form_valid(form)


from django.core.exceptions import PermissionDenied

class SMTPSettingsDeleteView(LoginRequiredMixin, DeleteView):
    model = SMTPSenderConfig
    success_url = reverse_lazy('smtp_settings_list')
    template_name = 'smtp_settings_confirm_delete.html'  # Optional confirmation page
    
    # Remove user ownership check completely
    def get_queryset(self):
        return SMTPSenderConfig.objects.all()  # No user filter
    
    def delete(self, request, *args, **kwargs):
        messages.success(request, "SMTP configuration deleted successfully")
        return super().delete(request, *args, **kwargs)
    
    def delete(self, request, *args, **kwargs):
        messages.success(request, "SMTP configuration deleted successfully")
        return super().delete(request, *args, **kwargs)




def signup(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('pass1')
        confirm_password = request.POST.get('pass2')
        
        # Validation checks
        if not email or not password or not confirm_password:
            messages.error(request, "All fields are required")
            return render(request, 'signup.html')
            
        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'signup.html')
        
        if CustomUser.objects.filter(email=email).exists():
            messages.info(request, "Email is already registered")
            return render(request, 'signup.html')

        try:
            # Create user with CustomUser model
            user = CustomUser.objects.create_user(
                email=email,
                password=password,
                is_active=False  # User remains inactive until email verification
            )
            
            # Send activation email
            email_subject = "Activate Your FormBuilder Account"
            message = render_to_string('activate.html', {
                'user': user,
                'domain': request.get_host(),  # Gets current domain (including port if development)
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': generate_token.make_token(user),
                'protocol': 'https' if request.is_secure() else 'http'
            })
            
            email_message = EmailMessage(
                email_subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [email]
            )
            
            # Try to send the email
            try:
                email_message.send()
                messages.success(
                    request,
                    "Account created successfully! Please check your email to activate your account."
                )
                return redirect('handlelogin')
                
            except Exception as email_error:
                # If email fails, delete the user and show error
                user.delete()
                messages.error(
                    request,
                    f"Failed to send activation email. Please try again later. Error: {str(email_error)}"
                )
                return render(request, 'signup.html')
                
        except Exception as e:
            messages.error(
                request,
                f"Error creating account: {str(e)}"
            )
            return render(request, 'signup.html')
    
    return render(request, 'signup.html')

class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None

        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            login(request, user)  # Optional: automatically log the user in
            messages.success(request, "Your account has been activated successfully!")
            return redirect('home')
        
        messages.error(request, "The activation link is invalid or has expired.")
        return redirect('handlelogin')

def handlelogin(request):
    if request.user.is_authenticated:
        return redirect('home')  
        
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('pass1')
        user = authenticate(request, email=email, password=password)
        
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', 'home')  
            return redirect(next_url)
        else:
            messages.error(request, "Invalid email or password")
    
    return render(request, "login.html")

def handlelogout(request):
    logout(request)
    messages.info(request,"Logout Success")
    return redirect('/auth/login')