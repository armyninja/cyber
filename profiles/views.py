from django.views.generic import FormView, RedirectView
from django.views.generic import DetailView, UpdateView
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth import get_user_model
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.http import HttpResponseNotFound
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator

from .forms import LoginForm, RegistrationForm, SetPasswordForm
from .forms import ForgotPasswordForm, ChangePasswordForm
from .models import Profile

from braces.views import LoginRequiredMixin

UserModel = get_user_model()


class RegisterProfile(FormView):

    form_class = RegistrationForm
    template_name = 'profiles/register.html'
    msg_success = "Account successfully registered"

    def get_success_url(self):
        return reverse('login')

    def form_valid(self, form):
        form.register_user()
        messages.add_message(self.request, messages.SUCCESS, self.msg_success)
        return super(RegisterProfile, self).form_valid(form)


class LoginProfile(FormView):

    form_class = LoginForm
    template_name = 'profiles/login.html'

    def get_success_url(self):
        return reverse('menu')

    def form_valid(self, form):
        login(self.request, form.get_user())
        return super(LoginProfile, self).form_valid(form)


class LogoutProfile(RedirectView):

    permanent = True

    def get_redirect_url(self):
        return reverse('home')

    def get(self, request, *args, **kwargs):
        logout(request)
        return super(LogoutProfile, self).get(request, *args, **kwargs)


class ViewProfile(LoginRequiredMixin, DetailView):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = 'profiles/profile.html'

    def get_object(self):
        return Profile.objects.get(email=self.request.user)


class EditProfile(LoginRequiredMixin, UpdateView):

    login_url = "login"
    redirect_unauthenticated_users = True

    model = Profile
    fields = ['alerts']
    template_name = 'profiles/update.html'

    def get_object(self):
        return Profile.objects.get(email=self.request.user)

    def get_success_url(self):
        return reverse('profile')


class ChangePassword(LoginRequiredMixin, FormView):

    form_class = ChangePasswordForm
    template_name = 'profiles/password.html'

    def get_form(self, form_class):
        # Overwrite original get_form function to add username to form params
        return form_class(self.request.user, **self.get_form_kwargs())

    def get_success_url(self):
        return reverse('profile')

    def form_valid(self, form):
        form.change_password()

        # Automatically re-authenticate so user doesn't have to login again
        user = authenticate(email=self.request.user,
                            password=form.cleaned_data['new_password2'])

        login(self.request, user)

        return super(ChangePassword, self).form_valid(form)


class ForgotPassword(FormView):

    msg_success = "Recovery instructions should arrive shortly to the registered account"
    form_class = ForgotPasswordForm
    template_name = 'profiles/recover.html'

    def get_success_url(self):
        return reverse('login')

    def form_valid(self, form):
        messages.add_message(self.request, messages.SUCCESS, self.msg_success)
        return super(ForgotPassword, self).form_valid(form)


class PasswordReset(FormView):
    # Template overwrite example derived from
    # http://ruddra.com/blog/2014/10/21/make-own-forgot-slash-reset-password-in-django/

    msg_success = "Password reset successfully"
    template_name = 'profiles/reset.html'
    form_class = SetPasswordForm

    def get_success_url(self):
        return reverse('login')

    def form_valid(self, form):
        messages.add_message(self.request, messages.SUCCESS, self.msg_success)
        return super(PasswordReset, self).form_valid(form)

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):

        form_class = self.get_form_class()

        assert uidb64 is not None and token is not None  # checked by URL conf

        try:
            uid = urlsafe_base64_decode(uidb64)
            user = UserModel._default_manager.get(pk=uid)

        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            form = self.get_form(form_class)

            if form.is_valid():
                form.change_password(user)
                return self.form_valid(form)
            else:
                return self.form_invalid(form)
        else:
            return HttpResponseNotFound('<h1>Invalid reset link</h1>')