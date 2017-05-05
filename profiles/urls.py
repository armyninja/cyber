from django.conf.urls import patterns, url

from .views import LoginProfile, RegisterProfile, LogoutProfile
from .views import ViewProfile, EditProfile, ChangePassword
from .views import ForgotPassword, PasswordReset


urlpatterns = patterns('',
    url(r'^$', ViewProfile.as_view(), name="profile"),
    url(r'^login/', LoginProfile.as_view(), name="login"),
    url(r'^logout/', LogoutProfile.as_view(), name="logout"),
    url(r'^register/', RegisterProfile.as_view(), name="register"),
    url(r'^update/', EditProfile.as_view(), name="update"),
    url(r'^password/', ChangePassword.as_view(), name="password"),
    url(r'^recover/', ForgotPassword.as_view(), name="recover"),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>.+)/$',
        PasswordReset.as_view(), name='reset'),
)