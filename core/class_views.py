from .forms import PleioAuthenticationForm, PleioAuthenticationTokenForm

from two_factor.forms import TOTPDeviceForm, BackupTokenForm
from two_factor.views.core import LoginView, SetupView
from .helpers import send_suspicious_login_message
from .models import PreviousLogins

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

        if 'device_id' in self.request.COOKIES:
            device_id = self.request.COOKIES['device_id']

            try:
                login = PreviousLogins.objects.get(device_id=device_id)
                previous_login_present = login.confirmed_login
            except:
                previous_login_present = False

            if previous_login_present:
                #cookie is present so no need to send an email and no further checking is requiered
                check_previous_logins = False
                PreviousLogins.update_previous_login(session, login.pk)

        if check_previous_logins:
            if not PreviousLogins.is_confirmed_login(session, device_id, email):
                #no confirmed matching login found, so email must be sent
                send_suspicious_login_message(self.request, device_id, email)

        return LoginView.done(self, form_list, **kwargs)
