from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib import auth
from django.conf import settings
from django.core import signing
from .models import User

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