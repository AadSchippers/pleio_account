from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.template import RequestContext, Template
from django.contrib import auth
from django.conf import settings
from django.core import signing
import uuid
import os

def send_activation_token(request, user):
    template_context = {
        'site': get_current_site(request),
        'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS,
        'activation_key': generate_activation_token(user.email)
    }

    user.email_user(
        render_to_string('emails/register_subject.txt', template_context),
        render_to_string('emails/register.txt', template_context),
        settings.DEFAULT_FROM_EMAIL
    )

def generate_activation_token(email):
    return signing.dumps(
        obj=email
    )

def activate_and_login_user(request, activation_key):
    from .models import User

    try:
        email = signing.loads(
            activation_key,
            max_age=settings.ACCOUNT_ACTIVATION_DAYS * 86400
        )

        if email is None:
            return False

        user = User.objects.get(email=email)

        if user.is_active:
            return False

        user.is_active = True
        user.save()

        auth.login(request, user)
        return True

    except (signing.BadSignature, User.DoesNotExist):
        return False

def unique_filepath(self, filename):
    ext = filename.split('.')[-1]
    filename = "%s.%s" % (uuid.uuid4(), ext)
    return os.path.join('avatars/', filename)

def send_suspicious_login_message(request, device_id, email):
    from .login_session_helpers import get_city, get_country

    session = request.session
    template_context = {
        'site': get_current_site(request),
        'user': email,
        'user_agent': session.user_agent,
        'ip_address': session.ip,
        'city': get_city(session.ip),
        'country': get_country(session.ip),
        'acceptation_key': generate_acceptation_token(device_id),
        'pleio_logo_small': request.build_absolute_uri("/static/images/pleio_logo_small.png")
    }

    email.email_user(
        render_to_string('emails/send_suspicious_login_message_subject.txt', template_context),
        render_to_string('emails/send_suspicious_login_message.txt', template_context),
        settings.DEFAULT_FROM_EMAIL,
        html_message = (render_to_string('emails/send_suspicious_login_message.html', template_context))
    )


def generate_acceptation_token(device_id):
    return signing.dumps(
        obj=device_id
    )

def accept_previous_logins(request, acceptation_key):
    from .models import PreviousLogins

    try:
        device_id = signing.loads(
            acceptation_key,
            max_age=settings.ACCOUNT_ACTIVATION_DAYS * 86400
        )

        if device_id is None:
            return False

        try:
            login = PreviousLogins.objects.get(device_id=device_id)
            login.confirmed_login = True
            login.save()
        except:
            pass

        return True

    except (signing.BadSignature, PreviousLogins.DoesNotExist):
        return False
