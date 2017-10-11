from .forms import PleioAuthenticationForm, PleioAuthenticationTokenForm

from two_factor.forms import TOTPDeviceForm, BackupTokenForm
from two_factor.views.core import LoginView, SetupView
from user_sessions.models import Session
from .helpers import send_login_check

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
        sc = self.request.session

        sf = Session.objects.all()
        sf = sf.filter(session_key=sc.session_key)
        sf = sf.filter(user=user)
        if sf.count() > 0:
#       session_key bestaat al, bekende sessie
#            print('sessie hergebruik')
        else:
#       session_key bestaat niet, controle op ip/user_agent nodig
#            print('controleer')
            sf = Session.objects.all()
            sf = sf.exclude(session_key=sc.session_key)
            sf = sf.filter(user=user)
            sf = sf.filter(ip=sc.ip)
            sf = sf.filter(user_agent=sc.user_agent)
            if sf.count() == 0:
#       session_key bestaat niet, nieuwe ip/user_agent
#                print('mail')
                send_login_check(self.request, user)

        return LoginView.done(self, form_list, **kwargs)



