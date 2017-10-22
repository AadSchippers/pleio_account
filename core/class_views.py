from .forms import PleioAuthenticationForm, PleioAuthenticationTokenForm

from two_factor.forms import TOTPDeviceForm, BackupTokenForm
from two_factor.views.core import LoginView, SetupView
from user_sessions.models import Session
from .helpers import send_suspicious_login_message
from .models import PreviousLogins
from django.db import models

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

        email = self.get_user()
        session = self.request.session

        if not PreviousLogins.is_confirmed_login(session, email):
            #           wanneer count == 0:  sessie komt niet voor in lijst, dus mail nodig
            send_suspicious_login_message(self.request, email)

        return LoginView.done(self, form_list, **kwargs)

