from django.contrib import admin
from .models import Profile, RegistrationToken


class RapidUserAdmin(admin.ModelAdmin):

    exclude = ('password',)
    list_display = ('email', 'last_login', 'is_active', 'is_staff', 'is_admin',)


class RegistrationTokenAdmin(admin.ModelAdmin):
    list_display = ('token', 'email')

admin.site.register(Profile, RapidUserAdmin)
admin.site.register(RegistrationToken, RegistrationTokenAdmin)