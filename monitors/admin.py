from django.contrib import admin
from .models import DomainMonitor, IpMonitor, IndicatorAlert, IndicatorTag


class IpMonitorAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'last_hosts', 'modified', 'owner')


class DomainMonitorAdmin(admin.ModelAdmin):
    list_display = ('domain_name', 'last_hosts', 'modified', 'owner')


class IndicatorAlertAdmin(admin.ModelAdmin):
    list_display = ('indicator', 'message', 'created', 'recipient')


class IndicatorTagAdmin(admin.ModelAdmin):
    list_display = ('tag', 'owner')


admin.site.register(IndicatorTag, IndicatorTagAdmin)
admin.site.register(IpMonitor, IpMonitorAdmin)
admin.site.register(DomainMonitor, DomainMonitorAdmin)
admin.site.register(IndicatorAlert, IndicatorAlertAdmin)