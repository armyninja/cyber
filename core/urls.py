from django.conf.urls import patterns, url
from .views import HomePage, PrimaryNavigation


urlpatterns = patterns('',
    url(r'^$', PrimaryNavigation.as_view(), name="menu")
)