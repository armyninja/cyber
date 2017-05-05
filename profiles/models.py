import os
import hashlib

from django.db import models
from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser)
from core.tasks import deliver_email


def generate_token():
    return hashlib.md5(os.urandom(32)).hexdigest()


class RegistrationToken(models.Model):

    token = models.CharField(max_length=32, primary_key=True, default=generate_token)
    email = models.EmailField()

    def save(self, *args, **kwargs):
        """ Custom save method to email token upon creation """

        register_url = reverse('register')
        full_url = settings.BASE_SITE_URL + register_url
        subject = "R.A.P.I.D Registration"
        body = '''The following token will allow you to register for the R.A.P.I.D tool: %s.
        Please visit the following URL %s and fill out the necessary information in order to
        complete the registration process. ''' % (str(self.token), full_url)

        deliver_email.delay(subject=subject, body=body, recipients=[str(self.email)])
        super(RegistrationToken, self).save(*args, **kwargs)


class ProfileManager(BaseUserManager):

    def create_user(self, email, password, **extra_fields):

        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email), **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):

        user = self.create_user(
            email=email,
            password=password,
            **extra_fields
        )

        user.is_staff = True
        user.is_admin = True
        user.save(using=self._db)
        return user


class Profile(AbstractBaseUser):
    id = models.AutoField(primary_key=True)
    email = models.EmailField(unique=True)
    alerts = models.BooleanField(default=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS = ['is_staff']

    objects = ProfileManager()

    def get_full_name(self):
        # The user is identified by their email address
        return self.email

    def get_short_name(self):
        # The user is identified by their email address
        return self.email

    @property
    def is_superuser(self):
        return self.is_admin

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin