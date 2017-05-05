from django import forms
from django.conf import settings
from django.core.urlresolvers import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator

from .models import RegistrationToken
from core.tasks import deliver_email


User = get_user_model()


class ProfileRequirements(object):

    def __init__(self):
        self.password_error = ""

    def password_format(self, password):
        """ Verify passwords meet complexity requirements """
        self.password_error = "Password must be between 8 and 32 characters long"
        min_length = 8
        max_length = 32

        if min_length < len(password) < max_length:
            return True
        else:
            return False


class LoginForm(forms.Form):
    """
    Form for authenticating users
    """
    email = forms.EmailField(required=True,
                             label='Email Address',
                             widget=forms.TextInput())

    password = forms.CharField(required=True,
                               label='Password',
                               widget=forms.PasswordInput())

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        self.user_cache = None
        super(LoginForm, self).__init__(*args, **kwargs)

    def clean(self):

        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')

        # Error messages for user feedback
        credential_error = "Please enter a valid email address and password"
        inactive_error = "The account is inactive"

        if email and password:
            self.user_cache = authenticate(email=email,
                                           password=password)

            if not self.user_cache:
                raise forms.ValidationError(credential_error)
            elif not self.user_cache.is_active:
                raise forms.ValidationError(inactive_error)

        return self.cleaned_data

    def get_user(self):
        return self.user_cache


class RegistrationForm(forms.Form):  # forms.ModelForm?
    """
    Form for registering users
    """
    email = forms.EmailField(required=True,
                             label='Email Address',
                             widget=forms.TextInput())

    password1 = forms.CharField(required=True,
                                label='Password',
                                widget=forms.PasswordInput())

    password2 = forms.CharField(required=True,
                                label='Password Confirmation',
                                widget=forms.PasswordInput())

    registration_code = forms.CharField(required=True,
                                        label='Registration Token',
                                        widget=forms.TextInput())

    def clean_email(self):
        """ Verify email address is not already in use """
        email = self.cleaned_data["email"]

        # Error messages for user feedback
        exists_error = "That email address is already registered"

        try:
            User.objects.get(email__exact=email)
            raise forms.ValidationError(exists_error)
        except User.DoesNotExist:
            return email

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")

        # Error messages for user feedback
        match_error = "Password fields did not match"

        # Load requirement checks
        checks = ProfileRequirements()

        if password1 != password2:
            raise forms.ValidationError(match_error)

        # Check if password does not meet format
        elif not checks.password_format(password2):
            raise forms.ValidationError(checks.password_error)

        return password2

    def clean_registration_code(self):
        token = self.cleaned_data.get('registration_code')

        # Error messages for user feedback
        token_error = "Invalid registration code"

        try:
            RegistrationToken.objects.get(token__exact=token)
        except ObjectDoesNotExist:
            raise forms.ValidationError(token_error)

        return token

    def register_user(self):
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password2')
        token = self.cleaned_data.get('registration_code')

        User.objects.create_user(email, password)
        RegistrationToken.objects.get(token__exact=token).delete()


class ChangePasswordForm(forms.Form):
    current_password = forms.CharField(required=True,
                                       label='Current Password',
                                       widget=forms.PasswordInput())

    new_password1 = forms.CharField(required=True,
                                    label='New Password',
                                    widget=forms.PasswordInput())

    new_password2 = forms.CharField(required=True,
                                    label='Verify Password',
                                    widget=forms.PasswordInput())

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(ChangePasswordForm, self).__init__(*args, **kwargs)

    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password')
        authenticated = authenticate(email=self.user,
                                     password=current_password)

        authentication_error = "Current password was incorrect"

        if authenticated:
            return current_password
        else:
            raise forms.ValidationError(authentication_error)

    def clean_new_password2(self):

        new_password1 = self.cleaned_data.get('new_password1')
        new_password2 = self.cleaned_data.get('new_password2')

        # Error messages for user feedback
        match_error = "New password fields did not match"

        # Load requirement checks
        checks = ProfileRequirements()

        if new_password1 != new_password2:
            raise forms.ValidationError(match_error)

        # Check if password does not meet format
        elif not checks.password_format(new_password2):
            raise forms.ValidationError(checks.password_error)

        return new_password2

    def change_password(self):
        new_password = self.cleaned_data.get('new_password2')

        user = User.objects.get(email__exact=self.user)
        user.set_password(new_password)
        user.save()


class ForgotPasswordForm(forms.Form):
    """
    Form for users who forgot password
    """
    email = forms.EmailField(required=True,
                             max_length=254,
                             label='Registered Email',
                             widget=forms.TextInput())

    def clean_email(self):

        email = self.cleaned_data.get('email')

        try:
            user = User.objects.get(email__exact=email, is_active=True)

        except User.DoesNotExist:
            pass

        else:

            uid = urlsafe_base64_encode(force_bytes(user.pk)).decode("utf-8")
            token = default_token_generator.make_token(user)

            reset_url = reverse('reset', kwargs={'uidb64': uid, 'token': token})
            full_url = settings.BASE_SITE_URL + reset_url

            subject = 'R.A.P.I.D Password Recovery'
            body = ''' A password reset request was received for your account
            with R.A.P.I.D. Please visit the following URL %s in order to
            complete the password reset process. If you did not request a
            password reset or were able to remember your previous password
            you may disregard this message. ''' % full_url

            deliver_email.delay(subject=subject, body=body, recipients=[email])

        return email


class SetPasswordForm(forms.Form):

    password1 = forms.CharField(required=True,
                                label='New Password',
                                widget=forms.PasswordInput())

    password2 = forms.CharField(required=True,
                                label='Verify Password',
                                widget=forms.PasswordInput())

    def clean_password2(self):

        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        # Error messages for user feedback
        match_error = "Password fields did not match"

        # Load requirement checks
        checks = ProfileRequirements()

        if password1 != password2:
            raise forms.ValidationError(match_error)

        # Check if password does not meet format
        elif not checks.password_format(password2):
            raise forms.ValidationError(checks.password_error)

        return password2

    def change_password(self, user):
        new_password = self.cleaned_data.get('password2')

        user = User.objects.get(email__exact=user)
        user.set_password(new_password)
        user.save()