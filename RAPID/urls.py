from django.conf.urls import patterns, include, url
from django.contrib import admin
import core.urls
import profiles.urls
import pivoteer.urls
import monitors.urls


urlpatterns = patterns('',
    url(r'^$', core.views.HomePage.as_view(), name="home"),
    url(r'^navigation/', include(core.urls)),
    url(r'^profile/', include(profiles.urls)),
    url(r'^pivoteer/', include(pivoteer.urls)),
    url(r'^monitors/', include(monitors.urls)),
    url(r'^admin/', include(admin.site.urls)),
)