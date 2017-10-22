from .forms import PleioAuthenticationForm, PleioAuthenticationTokenForm

from two_factor.forms import TOTPDeviceForm, BackupTokenForm
from two_factor.views.core import LoginView, SetupView
from user_sessions.models import Session
from .helpers import send_suspicious_login_message
from .models import PreviousLogins,User
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

        check_previous_logins = True

        if 'cookie_id' in self.request.COOKIES:
            cookie_id = self.request.COOKIES['cookie_id']

            try:
                login = PreviousLogins.objects.get(cookie_id=cookie_id)
                cookie_present = True
            except:
                cookie_present = False

            if cookie_present :
#           cookie aanwezig, geen e-mail sturen
                check_previous_logins = False
                PreviousLogins.set_last_login_date(login.pk)

        if check_previous_logins:
            if not PreviousLogins.is_confirmed_login(session, email):
#           wanneer count == 0:  sessie komt niet voor in lijst, dus e-mail nodig
                send_suspicious_login_message(self.request, email)

        return LoginView.done(self, form_list, **kwargs)

