from django.conf.urls import patterns, url

from .views import PivotManager, CheckTask, ExportRecords


urlpatterns = patterns('',
    url(r'^$', PivotManager.as_view(), name='app_Pivoteer'),
    url(r'^tasks', CheckTask.as_view(), name='Pivoteer_Tasks'),
    url(r'^exports', ExportRecords.as_view(), name='Pivoteer_Export'),
)