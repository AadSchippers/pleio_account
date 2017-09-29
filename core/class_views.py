from .forms import PleioAuthenticationForm, PleioAuthenticationTokenForm

from two_factor.forms import TOTPDeviceForm, BackupTokenForm
from two_factor.views.core import LoginView, SetupView

class PleioLoginView(LoginView):
    template_name = 'login.html'

    form_list = (
        ('auth', PleioAuthenticationForm),
        ('token', PleioAuthenticationTokenForm),
        ('backup', BackupTokenForm),
    )

    def done(self, form_list, **kwargs):
        if self.request.POST.get('auth-is_persistent'):
            self.request.session.set_expiry(30 * 24 * 60 * 60)
        else:
            self.request.session.set_expiry(0)

        return LoginView.done(self, form_list, **kwargs)


import logging
import warnings
from base64 import b32encode
from binascii import unhexlify

import django_otp
import qrcode
import qrcode.image.svg
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.sites.shortcuts import get_current_site
from django.forms import Form
from django.http import Http404, HttpResponse
from django.shortcuts import redirect, resolve_url
from django.utils.http import is_safe_url
from django.utils.module_loading import import_string
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import DeleteView, FormView, TemplateView
from django.views.generic.base import View
from django_otp.decorators import otp_required
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.util import random_hex

from two_factor import signals
from two_factor.models import get_available_methods
from two_factor.utils import totp_digits

from two_factor.forms import (
    AuthenticationTokenForm, BackupTokenForm, DeviceValidationForm, MethodForm,
    PhoneNumberForm, PhoneNumberMethodForm, TOTPDeviceForm, YubiKeyDeviceForm,
)
from two_factor.models import PhoneDevice, get_available_phone_methods
from two_factor.utils import backup_phones, default_device, get_otpauth_url
from two_factor.views.utils import IdempotentSessionWizardView, class_view_decorator



@class_view_decorator(never_cache)
@class_view_decorator(login_required)
class PleioSetupView(TemplateView):
    """
    View for handling OTP setup.

    """
    success_url = 'two_factor:setup_complete'
    qrcode_url = 'two_factor:qr'
    template_name = 'tf_setup.html'
    session_key_name = 'django_two_factor-qr_secret_key'
    initial_dict = {}

    def get_method(self):
        method_data = self.storage.validated_step_data.get('method', {})
        return method_data.get('method', None)

    def get(self, request, *args, **kwargs):
        """
        Start the setup wizard. Redirect if already enabled.
        """
        if default_device(self.request.user):
            return redirect(self.success_url)
        return super(PleioSetupView, self).get(request, *args, **kwargs)

    def done(self, form, **kwargs):
        """
        Save form and redirect.
        """
        # Remove secret key used for QR code generation
        try:
            del self.request.session[self.session_key_name]
        except KeyError:
            pass

        # TOTPDeviceForm
        device = form.save()

        django_otp.login(self.request, device)
        return redirect(self.success_url)

    def get_form_kwargs(self, step=None):
        kwargs = {}
        if step == 'generator':
            kwargs.update({
                'key': self.get_key(step),
                'user': self.request.user,
            })
        if step in ('validation', 'yubikey'):
            kwargs.update({
                'device': self.get_device()
            })
        metadata = self.get_form_metadata(step)
        if metadata:
            kwargs.update({
                'metadata': metadata,
            })
        return kwargs

    def get_key(self, step):
        self.storage.extra_data.setdefault('keys', {})
        if step in self.storage.extra_data['keys']:
            return self.storage.extra_data['keys'].get(step)
        key = random_hex(20).decode('ascii')
        self.storage.extra_data['keys'][step] = key
        return key

    def get_context_data(self, form, **kwargs):
        context = super(PleioSetupView, self).get_context_data(form, **kwargs)
        key = self.get_key('generator')
        rawkey = unhexlify(key.encode('ascii'))
        b32key = b32encode(rawkey).decode('utf-8')
        self.request.session[self.session_key_name] = b32key
        context.update({
            'QR_URL': reverse(self.qrcode_url)
        })
        context['cancel_url'] = resolve_url(settings.LOGIN_REDIRECT_URL)
        return context




