from django import forms


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