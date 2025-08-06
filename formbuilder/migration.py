from django.db import migrations

def assign_users(apps, schema_editor):
    CustomUser = apps.get_model('formbuilder', 'CustomUser')
    Form = apps.get_model('formbuilder', 'Form')
    SMTPSenderConfig = apps.get_model('formbuilder', 'SMTPSenderConfig')
    
    # Create a default admin user if none exists
    admin_user, created = CustomUser.objects.get_or_create(
        email='admin@example.com',
        defaults={
            'is_active': True,
            'is_staff': True,
            'is_superuser': True
        }
    )
    
    # Assign all existing forms and SMTP configs to admin
    Form.objects.filter(user__isnull=True).update(user=admin_user)
    SMTPSenderConfig.objects.filter(user__isnull=True).update(user=admin_user)

class Migration(migrations.Migration):
    dependencies = [
        # Your last migration
    ]

    operations = [
        migrations.RunPython(assign_users),
    ]