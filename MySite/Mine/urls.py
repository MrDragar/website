from django.urls import path
from . import views
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('login', csrf_exempt(views.login)),
    path('join/', csrf_exempt(views.join)),
    path('registration', csrf_exempt(views.registration)),
    path('hasJoined/', csrf_exempt(views.hasJoinsed)),
    path('profile/', csrf_exempt(views.profile)),
    path('modpack', csrf_exempt(views.modpack)),
    path('update', csrf_exempt(views.update)),
    path('version', csrf_exempt(views.version)),
    path('verification', views.get_verification),
    path('texture', csrf_exempt(views.get_skin)),
    path('home', views.home, name='home'),
    path('logging', views.site_log, name='login'),
    path('registr', views.site_registr, name='registration'),
    path('creator', views.creator, name='creator'),
    path('logout', views.logout, name='logout'),
    path('download_launcher', views.download_launcher, name='download_launcher'),
    path('account', views.account, name='account'),
    path('password_request', views.password_request, name='password_request'),
    path('password_editing', views.password_editing, name='password_editing'),
    path('username_editing', views.username_editing, name='username_editing'),
    path('username_request', views.username_request, name='username_request'),
    path('forget_password', views.forget_password, name='forget_password')

]
