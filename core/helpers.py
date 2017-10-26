from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib import auth
from django.conf import settings
from django.core import signing
import uuid
import os
from user_sessions.models import Session

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

def send_login_check(request, user):
    session = request.session
    template_context = {
        'site': get_current_site(request),
        'ip_address': session.ip,
        'user': user,
        'user_agent': session.user_agent,
    }

    user.email_user(
        render_to_string('emails/login_check_subject.txt', template_context),
        render_to_string('emails/login_check.txt', template_context),
        settings.DEFAULT_FROM_EMAIL
    )
