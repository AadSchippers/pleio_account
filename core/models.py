from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
from django.utils.text import slugify
from django.core.mail import send_mail
from django.contrib import admin
from django.db import models
from .helpers import unique_filepath

class Manager(BaseUserManager):
    def create_user(self, email, name, password=None, accepted_terms=False, receives_newsletter=False):
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            name=name
        )

        user.set_password(password)
        user.accepted_terms = accepted_terms
        user.receives_newsletter = receives_newsletter

        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password):
        user = self.create_user(
            email=self.normalize_email(email),
            name=name,
            password=password
        )

        user.is_admin = True
        user.is_active = True
        user.receives_newsletter = True

        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    objects = Manager()

    username = models.SlugField(unique=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=255, unique=True)
    accepted_terms = models.BooleanField(default=False)
    receives_newsletter = models.BooleanField(default=False)
    avatar = models.ImageField(upload_to=unique_filepath, null=True, blank=True)

    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)

    REQUIRED_FIELDS = ['name']
    USERNAME_FIELD = 'email'

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self._get_unique_username()

        super(User, self).save(*args, **kwargs)

    def __str__(self):
        return self.email

    def _get_unique_username(self):
        max_length = User._meta.get_field('username').max_length
        username = slugify(self.email.split("@")[0])
        unique_username = username[:max_length]
        i = 1

        while User.objects.filter(username=unique_username).exists():
            unique_username = '{}-{}'.format(username[:max_length - len(str(i)) - 1], i)
            i += 1

        return unique_username

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    def get_full_name(self):
        return self.name

    def get_short_name(self):
        return self.name

    def email_user(self, subject, message, from_email=None, **kwargs):
        send_mail(subject, message, from_email, [self.email], **kwargs)

    @property
    def is_staff(self):
        return self.is_admin

class Previous_logins(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    ip = models.GenericIPAddressField(null=True, blank=True, verbose_name='IP')
    location =  models.CharField(null=True, max_length=200)
    user_agent = models.CharField(null=True, blank=True, max_length=200)
    last_login_date = models.DateTimeField(
            default=timezone.now)
    confirmed_login = models.BooleanField(default=False)

    def add_known_login(session, user):
        print('user: ', user)
        login = Previous_logins.objects.create(
            user = user,
            ip = session.ip,
            location = None,
            user_agent = session.user_agent)
        login.save()

    def is_known_login(session, email):
        user = User.objects.get(email=email)

        login = Previous_logins.objects.all()
        login = login.filter(user=user)
        login = login.filter(ip=session.ip)
        login = login.filter(user_agent=session.user_agent)

        if login.count() == 0:
            self = Previous_logins
            self.add_known_login(session, user)
        else:
            for l in login:
                l.last_login_date = timezone.now()
                l.save()

        return (login.count() > 0)

    def confirm_login(self):
        self.confirmed_login = True
        self.save()



admin.site.register(User)