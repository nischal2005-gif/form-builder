from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin
from .models import *

class FieldInline(admin.TabularInline):
    model = Field
    extra = 1

@admin.register(Form)
class FormAdmin(admin.ModelAdmin):
    list_display = ('title', 'receiver_email', 'created_at')
    inlines = [FieldInline]
    search_fields = ('title', 'receiver_email')
    list_filter = ('created_at', 'recaptcha_enabled', 'email_confirmation_required')

class FieldResponseInline(admin.TabularInline):
    model = FieldResponse
    extra = 0
    readonly_fields = ('field', 'response')
    can_delete = False

@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ('form', 'submitted_at')
    inlines = [FieldResponseInline]
    readonly_fields = ('form', 'submitted_at')
    list_filter = ('submitted_at',)

@admin.register(SMTPSenderConfig)
class SMTPSenderConfigAdmin(admin.ModelAdmin):
    list_display = ('email', 'smtp_host', 'user', 'is_verified')
    actions = ['safe_delete']
    
    def delete_model(self, request, obj):
        try:
            # Clear references first
            obj.forms.update(smtp_config=None)
            obj.notifications.update(smtp_config=None)
            obj.delete()
            self.message_user(request, "SMTP config deleted successfully", messages.SUCCESS)
        except Exception as e:
            self.message_user(request, f"Error deleting config: {str(e)}", messages.ERROR)
    
    def safe_delete(self, request, queryset):
        for config in queryset:
            try:
                config.forms.update(smtp_config=None)
                config.notifications.update(smtp_config=None)
                config.delete()
            except Exception as e:
                self.message_user(request, f"Error deleting config {config.email}: {str(e)}", messages.ERROR)
        self.message_user(request, f"Deleted {queryset.count()} configs safely", messages.SUCCESS)
    
    safe_delete.short_description = "Delete safely (clear references first)"

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_staff')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)
    actions = ['safe_delete_user']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Verification', {'fields': ('is_verified', 'verification_token', 'token_created_at')}),
    )
    
    def safe_delete_user(self, request, queryset):
        """Custom admin action to safely delete users and related objects"""
        for user in queryset:
            try:
                # Delete in proper order to maintain referential integrity
                Notification.objects.filter(form__user=user).delete()
                Submission.objects.filter(form__user=user).delete()
                Field.objects.filter(form__user=user).delete()
                Form.objects.filter(user=user).delete()
                SMTPSenderConfig.objects.filter(user=user).delete()
                user.delete()
                self.message_user(request, f"Successfully deleted user {user.email}", messages.SUCCESS)
            except Exception as e:
                self.message_user(request, f"Error deleting user {user.email}: {str(e)}", messages.ERROR)
    
    safe_delete_user.short_description = "Delete selected users (with all related data)"
    
    def get_actions(self, request):
        actions = super().get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']  # Remove the default delete action
        return actions