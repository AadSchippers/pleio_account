from .forms import PleioAuthenticationForm, PleioAuthenticationTokenForm

from two_factor.forms import TOTPDeviceForm, BackupTokenForm
from two_factor.views.core import LoginView, SetupView
from user_sessions.models import Session
from .helpers import send_login_check
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

        user = self.get_user()
        session_current = self.request.session
        mail_needed = False

        session_filtered = Session.objects.all()
        session_filtered = session_filtered.filter(session_key=session_current.session_key)
        session_filtered = session_filtered.filter(user=user)
#       wanneer count > 0: session_key bestaat al, bekende sessie: geen mail nodig
        if session_filtered.count() == 0:
#       session_key bestaat niet, controle op ip/user_agent nodig
            print('controleer')
            session_filtered = Session.objects.all()
            session_filtered = session_filtered.exclude(session_key=session_current.session_key)
            session_filtered = session_filtered.filter(user=user)
            session_filtered = session_filtered.filter(ip=session_current.ip)
            session_filtered = session_filtered.filter(user_agent=session_current.user_agent)
            mail_needed = (session_filtered.count() == 0)

        self.request.session['mail_needed'] = mail_needed

        return LoginView.done(self, form_list, **kwargs)


