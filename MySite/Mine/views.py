import json
from django.http import JsonResponse, HttpResponse, FileResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from validate_email import validate_email
from .models import players, versions
from random import randint
from hashlib import md5
import os
from shutil import copyfile
import datetime
import base64
from django.core.mail import EmailMessage
from .forms import PlayerForm, LoginForm, SkinForm, CapeForm, PasswordForm, UsernameForm, EmailForm
import time


# Creating accessToken
def create_access():
    a = str(randint(1000000000, 2147483647)) + str(randint(1000000000, 2147483647)) + str(randint(0, 9))
    access_token1 = md5(bytes(a, 'utf-8')).hexdigest()
    return access_token1


# Creating uuid
def create_uuid(email, password):
    uuid = email + password + create_access()
    return md5(bytes(uuid, 'utf-8')).hexdigest()


# Logging
def login(request):
    try:
        name = str(request.POST['username'])
        password = md5(bytes(request.POST['password'], 'utf-8')).hexdigest()
        new_token = create_access()
    except:
        return JsonResponse({
            'status': 'ERROR', 'message': ' Error of POST'
        })

    try:
        players.objects.get(username=name)
        try:
            a = players.objects.get(username=name, password=password)
        except:
            return JsonResponse({'status': 'ERROR', 'message': ' Incorrect password'})
        if not a.verification:
            return JsonResponse({'status': 'ERROR', 'message': ' Involved verification'})
        a.accessToken = new_token
        a.save()
        response = {
            'status': 'OK',
            'message': a.username + ':' + a.uuid + ':' + a.accessToken
        }

        return JsonResponse(response)
    except:
        return JsonResponse({'status': 'ERROR', 'message': 'Nonexistent name'})


def registration(request):
    try:
        host = (request.get_host())
        name = str(request.POST["username"])
        password1 = str(request.POST["password1"])
        password2 = str(request.POST["password2"])
        mail = str(request.POST["email"])
        while mail[-1] == ' ':
            mail = mail[0:-1]
    except:
        return JsonResponse({'status': 'ERROR', 'message': ' Error of POST'})
    if not (validate_email(mail)):
        return JsonResponse({'status': 'ERROR', 'message': ' Your email is not validated'})
    try:
        players.objects.get(email=mail)
        return JsonResponse({'status': 'ERROR', 'message': 'This email already exists'})
    except:
        pass
    try:
        players.objects.get(username=name)
        return JsonResponse({'status': 'ERROR', 'message': 'This name already exists'})
    except:
        if password1 != password2:
            return JsonResponse({'status': 'ERROR', 'message': 'Passwords are not same'})
        uuid = create_uuid(mail, password1)
        New_object = players(username=name, password=md5(bytes(password1, 'utf-8')).hexdigest(),
                             accessToken=create_access(), uuid=uuid,
                             email=mail, verification=False)
        url = host + '/verification?email=' + mail + '&uuid=' + uuid
        try:
            send_verification(mail=mail, url=url)
        except:
            return JsonResponse({'status': 'ERROR', 'message': ' Error of send a latter to'
                                                               'your email'})
        New_object.save()

        return JsonResponse({'status': 'OK', 'message': 'You was registered successfully'})


def join(request):
    try:
        json_string = request.body.decode()
        data = json.loads(json_string)

        uuid = str(data["selectedProfile"])
        accessToken = str(data["accessToken"])
        serverID = str(data["serverId"])
    except:
        return JsonResponse({
            'error': 'ERROR', 'cause': ' Error of POST'
        })
    try:
        a = players.objects.get(uuid=uuid, accessToken=accessToken)
        a.serverID = serverID
        a.save()
        return HttpResponse()
    except:
        return JsonResponse({
            'error': 'ERROR', 'cause': ' Invalid username or password.'
        })


def get_url(name1, type1, host):
    if not (os.path.exists('Mine/static/Mine/texture/' + type1 + '/' + name1 + '.png')):
        return ''
    name2 = str(md5(bytes(name1 + type1, 'utf-8')).hexdigest()) + '.png'
    copyfile('Mine/static/Mine/texture/' + type1 + '/' + name1 + '.png', 'Mine/static/Mine/skins/' + name2)
    return host + '/static/Mine/skins/' + name2


def get_profile(name, uuid, host):
    skin = get_url(name, 'skin', 'http://' + host)
    cape = get_url(name, 'cape', 'http://' + host)
    first_date = datetime.datetime(1970, 1, 1)
    time_since = datetime.datetime.now() - first_date
    seconds = int(time_since.total_seconds())
    textures = {}
    if skin != '':
        textures['SKIN'] = {'url': skin}
    if cape != '':
        textures['CAPE'] = {'url': cape}
    property = {
        'timestamp': str(seconds),
        'profileId': uuid,
        'profileName': name,
        'textures': textures
    }
    a = json.dumps(property)
    prof = {
        'id': uuid,
        'name': name,
        'properties': [{
            "name": "textures",
            'value': (base64.b64encode(a.encode('utf-8'))).decode(),
            "signature": ''

        }]

    }
    return prof


def hasJoinsed(request):
    host = (request.get_host())
    username = request.GET['username']
    b = players.objects.get(username=username)
    name = b.username
    uuid = b.uuid
    a = get_profile(name, uuid, host)
    return JsonResponse(a)


def profile(request):
    host = request.get_host()
    uuid = request.GET['uuid']
    un = request.GET['unsigned']
    if un == 'false':
        return HttpResponse()
    b = players.objects.get(uuid=uuid)
    name = b.username
    a = get_profile(name, uuid, host)
    return JsonResponse(a)


def modpack(request):
    OS = request.POST["OS"]
    if OS == "linux":
        name = 'MyModPackLinux.zip'
    elif OS == 'windows':
        name = 'MyModPack.zip'
    f = open('zip/' + name, 'rb')
    return FileResponse(f)


def update(request):
    f = open('zip/Launcher.zip', 'rb')
    return FileResponse(f)


def version(request):
    version = versions.objects.order_by('id')[0]
    data = {
        'number': version.number,
        'changes': version.changes,
    }
    return JsonResponse(data)


def send_verification(mail, url):
    email = EmailMessage('Проверка почты', 'В целях подтверждения почты пройдите по ссылке '
                         + 'http://' + url +
                         ' Если вы не регистрировались на сервере MyLauncher, проигнорируйте это сообщение.',
                         to=[mail])
    email.send()


def get_verification(request):
    content = {}
    if 'web_token' in request.session:
        del request.session['web_token']
    content['no_auth'] = True
    mail = request.GET['email']
    uuid = request.GET['uuid']
    if not players.objects.filter(email=mail, uuid=uuid).exists():
        content['title'] = 'Ошибка'
        content['message'] = "Игрока с такой почтой не существует"
        return render(request, 'Mine/verification.html', content)
    player = players.objects.get(email=mail, uuid=uuid)
    if player.verification == True:
        content['title'] = '666'
        content['message'] = "Почта уже подтверждена. " \
                             "Повторный переход по этой ссылке приводит к установки вируса на ваш" \
                             " компьютер. АХХАХАХАХА"
        return render(request, 'Mine/verification.html', content)
    player.verification = True
    player.save()
    content['title'] = 'Почта проверена'
    content['message'] = "Вы успешно подтвердили почту. " \
                         "Вы умнее 99% людей на этой планете. Темерь можно спокойно играть."
    return render(request, 'Mine/verification.html', content)


def get_skin(request):
    print(1)
    for i in request.FILES:
        name = i
    skin = request.FILES[name]
    f = open('Mine/static/Mine/texture/' + name, 'wb')
    f.write(skin.read())
    return HttpResponse()


def home(request):
    content = {'body': 'Тут будет что-то интересное ... возможно'}
    if 'web_token' in request.session:
        web_token = request.session['web_token']
        if players.objects.filter(web_token=web_token).exists():
            content['auth'] = True
        else:
            content['no_auth'] = True
    else:
        content['no_auth'] = True

    return render(request, 'Mine/index.html', content)


def generate_web_token():
    this_time = time.time()
    token = md5(bytes(str((int(this_time))), 'UTF-8')).hexdigest()
    return token


def site_log(request):
    content = {}
    if 'web_token' in request.session:
        del request.session['web_token']
    error = ''
    if request.method == 'POST':
        form = LoginForm(request.POST)
        print(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            mail = data["email"]
            password = md5(bytes(data['password'], 'utf-8')).hexdigest()
            try:
                players.objects.get(email=mail)
            except:
                error = "Нет такой почты"
                content = {'form': form, "error": error}
                content['no_auth'] = True
                return render(request, 'Mine/login.html', content)

            try:
                a = players.objects.get(email=mail, password=password)
            except:
                error = 'Неправильный пароль'
                content = {'form': form, "error": error}
                content['no_auth'] = True
                return render(request, 'Mine/login.html', content)
            if not a.verification:
                error = 'Вы не подтвердили почту'
                content = {'form': form, "error": error}
                content['no_auth'] = True
                return render(request, 'Mine/login.html', content)
            new_token = generate_web_token()
            a.web_token = new_token
            a.save()
            request.session['web_token'] = new_token
            content['auth'] = True
            return render(request, 'Mine/success_of_login.html', content)
    form = LoginForm()
    content = {'form': form, "error": error}
    content['no_auth'] = True
    return render(request, 'Mine/login.html', content)


def site_registr(request):
    if 'web_token' in request.session:
        del request.session['web_token']
    error = ''
    if request.method == 'POST':
        form = PlayerForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data
            host = request.get_host()

            name = content["username"]
            password1 = content["password1"]
            password2 = content["password2"]
            mail = content["email"]
            while mail[-1] == ' ':
                mail = mail[0:-1]

            if not (validate_email(mail)):
                error = 'Почта не действительна'
                data = {'form': form, 'error': error}
                data['no_auth'] = True
                return render(request, 'Mine/registration.html', data)
                pass
            if players.objects.filter(email=mail).exists():
                error = 'Почта уже существует'
                data = {'form': form, 'error': error}
                data['no_auth'] = True
                return render(request, 'Mine/registration.html', data)
            if players.objects.filter(username=name).exists():
                error = 'Имя игрока уже существует'
                data = {'form': form, 'error': error}
                data['no_auth'] = True
                return render(request, 'Mine/registration.html', data)
            if password1 != password2:
                error = 'Пароли не совпадают'
                data = {'form': form, 'error': error}
                data['no_auth'] = True
                return render(request, 'Mine/registration.html', data)
            uuid = create_uuid(mail, password1)
            New_object = players(username=name, password=md5(bytes(password1, 'utf-8')).hexdigest(),
                                 accessToken=create_access(), uuid=uuid,
                                 email=mail, verification=False)
            url = host + '/verification?email=' + mail + '&uuid=' + uuid

            try:
                send_verification(mail=mail, url=url)
            except:
                error = 'Почта не действительна'
                data = {'form': form, 'error': error}
                data['no_auth'] = True
                return render(request, 'Mine/registration.html', data)
            New_object.save()
            data = {}
            data['no_auth'] = True
            return render(request, 'Mine/success_of_registration.html', data)
        else:
            form = PlayerForm()
    else:
        form = PlayerForm()
    data = {'form': form, 'error': error, 'no_auth': True}
    return render(request, 'Mine/registration.html', data)


def creator(request):
    content = {'body': 'Тут будет что-то интересное ... возможно'}

    if 'web_token' in request.session:
        web_token = request.session['web_token']
        if players.objects.filter(web_token=web_token).exists():
            content['auth'] = True
        else:
            content['no_auth'] = True
    else:
        content['no_auth'] = True

    return render(request, 'Mine/creator.html', content)


def logout(request):
    if 'web_token' in request.session:
        del request.session['web_token']
    return render(request, 'Mine/exit.html', {'no_auth': True})


def download_launcher(request):
    content = {}

    if 'web_token' in request.session:
        web_token = request.session['web_token']
        if players.objects.filter(web_token=web_token).exists():
            content['auth'] = True
        else:
            content['no_auth'] = True
    else:
        content['no_auth'] = True

    if 'no_auth' in content:
        return render(request, 'Mine/no_auth.html', content)

    return render(request, 'Mine/download_launcher.html', content)


def account(request):
    content = {}
    if 'web_token' in request.session:
        web_token = request.session['web_token']
        if players.objects.filter(web_token=web_token).exists():
            content['auth'] = True
        else:
            content['no_auth'] = True
    else:
        content['no_auth'] = True
    if 'no_auth' in content:
        return render(request, 'Mine/no_auth.html', content)

    user = players.objects.get(web_token=web_token)
    content['username'] = user.username
    content['email'] = user.email
    skin_path = os.path.join('Mine/static/Mine/texture/skin', user.username + '.png')
    cape_path = os.path.join('Mine/static/Mine/texture/cape', user.username + '.png')
    if request.method == 'POST':
        skin_form = SkinForm(request.POST, request.FILES)
        cape_form = CapeForm(request.POST, request.FILES)
        if skin_form.is_valid():
            print(1)
            f = open(skin_path, 'wb')
            f.write(request.FILES['skin'].read())
            f.close()
            return redirect('account')

        elif cape_form.is_valid():
            print(2)
            f = open(cape_path, 'wb')
            f.write(request.FILES['cape'].read())
            f.close()
            return redirect('account')

    if os.path.exists(skin_path):
        content['skin'] = True

    if os.path.exists(cape_path):
        content['cape'] = True
    skin_form = SkinForm()
    cape_form = CapeForm()
    content['skin_form'] = skin_form
    content['cape_form'] = cape_form
    return render(request, 'Mine/account.html', content)


def generate_operation_token(operation_type, username):
    return md5(bytes(str(int(time.time())) + operation_type + username, 'UTF-8')).hexdigest()


def send_password_letter(url, mail):
    email = EmailMessage('Смена пароля', 'В целях подтверждения действия пройдите по ссылке '
                         + 'http://' + url +
                         ' \r\n \r\n \r\n \r\n'
                         ' Если вы не совершали запрос на смену пароля, срочно поменяйте пароль для '
                         'безопасности аккаунту ',
                         to=[mail])
    email.send()


def password_request(request):
    content = {}
    if 'web_token' in request.session:
        web_token = request.session['web_token']
        if players.objects.filter(web_token=web_token).exists():
            content['auth'] = True
        else:
            content['no_auth'] = True
    else:
        content['no_auth'] = True
    if 'no_auth' in content:
        return render(request, 'Mine/no_auth.html', content)
    user = players.objects.get(web_token=web_token)
    host = (request.get_host())
    password_token = generate_operation_token(operation_type='changing_password', username=user.username)
    user.password_token = password_token
    user.save()
    url = host + '/password_editing?password_token=' + password_token
    send_password_letter(url, user.email)
    return render(request, 'Mine/sending_letter.html', content)


def password_editing(request):
    content = {}
    if 'web_token' in request.session:
        web_token = request.session['web_token']
        if players.objects.filter(web_token=web_token).exists():
            content['auth'] = True
        else:
            content['no_auth'] = True
    else:
        content['no_auth'] = True

    if "password_token" in request.GET:
        password_token = request.GET["password_token"]
    else:
        return render(request, 'Mine/editing_error.html', content)
    if password_token == '':
        return render(request, 'Mine/editing_error.html', content)
    content['password_token'] = password_token
    if not players.objects.filter(password_token=password_token).exists():
        return render(request, 'Mine/editing_error.html', content)
    user = players.objects.get(password_token=password_token)
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            password1 = data["password1"]
            password2 = data["password2"]
            if password1 != password2:
                error = 'Пароли не совпадают'
                content["form"] = form
                content["error"] = error
                return render(request, 'Mine/editing_password.html', content)
            if user.password == md5(bytes(password1, "UTF-8")).hexdigest():
                error = 'Пароль совпадает с предыдущим'
                content["form"] = form
                content["error"] = error
                return render(request, 'Mine/editing_password.html', content)
            user.password = md5(bytes(password1, 'UTF-8')).hexdigest()
            user.web_token = generate_web_token()
            user.password_token = ''
            user.save()
            if 'web_token' in request.session:
                if web_token != user.web_token:
                    if 'auth' in content:
                        del content['auth']
                        content['no_auth'] = True
            return render(request, 'Mine/success_of_editing_password.html', content)
    form = PasswordForm()
    content["form"] = form
    return render(request, 'Mine/editing_password.html', content)


def username_request(request):
    content = {}
    if 'web_token' in request.session:
        web_token = request.session['web_token']
        if players.objects.filter(web_token=web_token).exists():
            content['auth'] = True
        else:
            content['no_auth'] = True
    else:
        content['no_auth'] = True
    if 'no_auth' in content:
        return render(request, 'Mine/no_auth.html', content)
    user = players.objects.get(web_token=web_token)
    host = (request.get_host())
    nickname_token = generate_operation_token(operation_type='changing_username', username=user.username)
    user.nickname_token = nickname_token
    user.save()
    url = host + '/username_editing?nickname_token=' + nickname_token
    send_password_letter(url, user.email)
    return render(request, 'Mine/sending_letter.html', content)


def username_editing(request):
    content = {}
    if 'web_token' in request.session:
        web_token = request.session['web_token']
        if players.objects.filter(web_token=web_token).exists():
            content['auth'] = True
        else:
            content['no_auth'] = True
    else:
        content['no_auth'] = True
    if 'no_auth' in content:
        return render(request, 'Mine/no_auth.html', content)

    if "nickname_token" in request.GET:
        nickname_token = request.GET["nickname_token"]
    else:
        return render(request, 'Mine/editing_error.html', content)
    if nickname_token == '':
        return render(request, 'Mine/editing_error.html', content)
    content['nickname_token'] = nickname_token
    if not players.objects.filter(nickname_token=nickname_token).exists():
        return render(request, 'Mine/editing_error.html', content)
    user = players.objects.get(nickname_token=nickname_token)
    user2 = players.objects.get(web_token=web_token)
    if user != user2:
        return render(request, 'Mine/no_auth.html', content)

    if request.method == 'POST':
        form = UsernameForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            username1 = data["username1"]
            username2 = data["username2"]
            password = data['password']
            if username1 != username2:
                error = 'Новые имена пользователя не совпадают'
                content["form"] = form
                content["error"] = error
                return render(request, 'Mine/editing_username.html', content)
            if user.username == username1:
                error = 'Новое имя пользователя совпадает с предыдущим'
                content["form"] = form
                content["error"] = error
                return render(request, 'Mine/editing_username.html', content)
            if user.password != md5(bytes(password, 'UTF-8')).hexdigest():
                error = 'Неправильный пароль'
                content["form"] = form
                content["error"] = error
                return render(request, 'Mine/editing_username.html', content)
            if players.objects.filter(username=username1).exists():
                error = 'Новое имя пользователя уже существует'
                content["form"] = form
                content["error"] = error
                return render(request, 'Mine/editing_username.html', content)
            user.username = username1
            user.web_token = generate_web_token()
            user.nickname_token = ''
            user.save()
            if "auth" in content:
                del content['auth']
                content['no_auth'] = True
            return render(request, 'Mine/success_of_editing_username.html', content)
    form = UsernameForm()
    content["form"] = form
    return render(request, 'Mine/editing_username.html', content)


def forget_password(request):
    content = {}
    if 'web_token' in request.session:
        del request.session['web_token']
    content['no_auth'] = True

    if request.method == 'POST':
        form = EmailForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            email = data['email']
            if not players.objects.filter(email=email).exists():
                print(email)
                content['form'] = form
                content['error'] = 'Такой почты не существует'
                return render(request, 'Mine/forget_password.html', content)
            user = players.objects.get(email=email)
            host = request.get_host()
            password_token = generate_operation_token(operation_type='changing_password', username=user.username)
            user.password_token = password_token
            user.save()
            url = host + '/password_editing?password_token=' + password_token
            send_password_letter(url, user.email)
            return render(request, 'Mine/sending_letter.html', content)
    form = EmailForm()
    content["form"] = form
    return render(request, 'Mine/forget_password.html', content)
