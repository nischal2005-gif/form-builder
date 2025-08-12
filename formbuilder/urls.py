from django.urls import path
from .views import *
from django.contrib.auth.decorators import login_required
from django.views.generic import RedirectView

urlpatterns = [
    # Redirect root URL to login page
    path('', RedirectView.as_view(url='/auth/login/', permanent=False)),
    
    # Authentication URLs
    path('auth/signup/', signup, name='signup'),
    path('auth/login/', handlelogin, name='handlelogin'),
    path('auth/logout/',handlelogout, name='handlelogout'),
    path('activate/<uidb64>/<token>/', ActivateAccountView.as_view(), name='activate'),
    
    # Protected URLs (require login)
    path('dashboard/', login_required(dashboard), name='dashboard'),
    path('home/', login_required(home), name='home'),  
    
    # Form-related URLs
    path('forms/', login_required(home), name='forms_home'),  
    path('form/create/', login_required(create_form), name='create_form'),
    path('forms/<uuid:form_id>/', login_required(form_view), name='form_view'),
    path('forms/<uuid:form_id>/edit/', login_required(edit_form), name='edit_form'),
    path('forms/<uuid:form_id>/delete/', login_required(delete_form), name='delete_form'),
    
    # Notification URLs
    path('forms/<uuid:form_id>/notifications/', login_required(manage_notifications), name='manage_notifications'),
    path('forms/<uuid:form_id>/notifications/add/', login_required(add_notification), name='add_notification'),
    path('forms/<uuid:form_id>/notifications/confirmation/', login_required(update_confirmation), name='update_confirmation'),
    path('notifications/<int:notification_id>/delete/', login_required(delete_notification), name='delete_notification'),
    
    # SMTP Settings URLs
    path('settings/smtp/', login_required(SMTPSettingsListView.as_view()), name='smtp_settings_list'),
    path('settings/smtp/add/', login_required(SMTPSettingsCreateView.as_view()), name='smtp_settings_add'),
    path('settings/smtp/<int:pk>/edit/', login_required(SMTPSettingsUpdateView.as_view()), name='smtp_settings_edit'),
    path('settings/smtp/<int:pk>/delete/', login_required(SMTPSettingsDeleteView.as_view()), name='smtp_settings_delete'),
    
    # API URLs
    path('api/verify_smtp_sender/', login_required(verify_smtp_sender), name='verify_smtp_sender'),
    path('forms/<uuid:form_id>/api/', login_required(api_docs), name='api_docs'),
]
