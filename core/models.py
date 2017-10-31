from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
from django.utils.text import slugify
from django.core.mail import send_mail
from django.contrib import admin
from django.db import models
from .helpers import unique_filepath
from .login_session_helpers import get_city, get_country, get_device, get_lat_lon

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

class PreviousLogins(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE, db_index=True)
    device_id = models.CharField(max_length=40, editable=False, null=True, db_index=True)
    ip = models.GenericIPAddressField(null=True, blank=True, verbose_name='IP')
    user_agent = models.CharField(null=True, blank=True, max_length=200)
    city = models.CharField(null=True, blank=True, max_length=100)
    country = models.CharField(null=True, blank=True, max_length=100)
    latitude = models.DecimalField(max_digits=5, decimal_places=3, null=True)
    longitude = models.DecimalField(max_digits=6, decimal_places=3, null=True)
    last_login_date = models.DateTimeField(default=timezone.now)
    confirmed_login = models.BooleanField(default=False)

    def add_known_login(session, device_id, user):
        lat_lon = get_lat_lon(session.ip)
        try:
            latitude = lat_lon[0]
            longitude = lat_lon[1]
        except:
            latitude = None
            longitude = None

        login = PreviousLogins.objects.create(
            user = user,
            device_id =  device_id,
            ip = session.ip,
            user_agent = get_device(session.user_agent),
            city = get_city(session.ip),
            country = get_country(session.ip),
            latitude = latitude,
            longitude = longitude,
         )
        login.save()

    def is_confirmed_login(session, device_id, email):
        user = User.objects.get(email=email)

        login = PreviousLogins.objects.all()
        login = login.filter(user=user)
        login = login.filter(ip=session.ip)
        login = login.filter(user_agent=get_device(session.user_agent))

        known_login = (login.count() > 0)

        if not known_login:
            PreviousLogins.add_known_login(session, device_id, user)
        else:
            l = login[0]
            PreviousLogins.update_previous_login(session, l.pk)

        login = login.filter(confirmed_login=True)
        confirmed_login = (login.count() > 0)

        return confirmed_login

    def update_previous_login(session, pk):
        l = PreviousLogins.objects.get(pk=pk)
        try:
            l.last_login_date = timezone.now()
            l.ip = session.ip
            l.user_agent = get_device(session.user_agent)
            l.city = get_city(session.ip)
            l.country = get_country(session.ip)
            l.lat_lon = get_lat_lon(session.ip)
            l.save()
        except:
            pass

admin.site.register(User)