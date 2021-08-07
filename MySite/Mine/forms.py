from django import forms


class PlayerForm(forms.Form):
    password1 = forms.CharField(max_length=32, widget=forms.PasswordInput(attrs={"class": "form-control"}),
                                label='Пароль')
    password2 = forms.CharField(max_length=32, widget=forms.PasswordInput(attrs={"class": "form-control"}),
                                label='Повтор пароля')
    email = forms.EmailField(max_length=40, widget=forms.EmailInput(attrs={"class": "form-control"}), label='Почта')
    username = forms.CharField(max_length=32, widget=forms.TextInput(attrs={"class": "form-control"}),
                               label='Имя игрока')
    check = forms.BooleanField(label='Вам 100% есть 18 лет')


class LoginForm(forms.Form):
    password = forms.CharField(max_length=32, widget=forms.PasswordInput(attrs={"class": "form-control"}),
                               label='Пароль')
    email = forms.EmailField(max_length=32, widget=forms.EmailInput(attrs={"class": "form-control"}),
                             label='Почта')
    check = forms.BooleanField(label='Вы 100% не бот')


class SkinForm(forms.Form):
    skin = forms.ImageField(widget=forms.FileInput(attrs={"class": "form-img", "onchange": "form.submit()"}))


class CapeForm(forms.Form):
    cape = forms.ImageField(widget=forms.FileInput(attrs={"class": "form-img", "onchange": "form.submit()"}))


class PasswordForm(forms.Form):
    password1 = forms.CharField(max_length=32, widget=forms.PasswordInput(attrs={"class": "form-control"}),
                                label="Новый пароль")
    password2 = forms.CharField(max_length=32, widget=forms.PasswordInput(attrs={"class": "form-control"}),
                                label="Повтор нового пароля")
    check = forms.BooleanField(label="Я точно хочу изменить пароль")


class UsernameForm(forms.Form):
    username1 = forms.CharField(max_length=32, widget=forms.TextInput(attrs={"class": "form-control"}),
                                label='Новое имя')
    username2 = forms.CharField(max_length=32, widget=forms.TextInput(attrs={"class": "form-control"}),
                                label='Повтор нового имени')
    password = forms.CharField(max_length=32, widget=forms.PasswordInput(attrs={"class": "form-control"}),
                               label='Пароль')
    check = forms.BooleanField(label='Я точно хочу изменить имя пользователя')


class EmailForm(forms.Form):
    email = forms.EmailField(max_length=32, widget=forms.EmailInput(attrs={"class": "form-control"}),
                             label="Ваша почта")
    check = forms.BooleanField(label='Просто ещё одна обязательная галочка')
