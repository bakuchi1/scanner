from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, logout
from django.contrib.auth import login as Login
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
import json
from .forms import RegisterForm
from .models import User
from django import forms
from .plugins.encrypt import md5
from .plugins.bootstrap import BootStrapModelForm
# Create your views here.
class loginForm(forms.Form):
    username = forms.CharField(label='username',widget=forms.TextInput(attrs={'class':'form-control'}),required=True)
    password = forms.CharField(label='password',widget=forms.PasswordInput(attrs={'class':'form-control'},render_value=True),required=True)

    def clean_password(self):
        pwd = self.cleaned_data.get('password')
        return md5(pwd)
def login(request):
    if request.method == "GET":
        form = loginForm()
        return render(request, 'login.html', {'form': form})
    form = loginForm(data=request.POST)
    if form.is_valid():

        user_object = User.objects.filter(name=form.cleaned_data['username'], password=form.cleaned_data['password']).first()
        if not user_object:
            form.add_error('password', 'username or password not correct')
            return render(request, 'login.html', {'form': form})

        request.session['info'] = {'id':user_object.id, 'name':user_object.name}
        return redirect('http://127.0.0.1:8000/vulnscan/')
    return render(request, 'login.html', {'form': form})


class registerform(BootStrapModelForm):
    confirm_password = forms.CharField(label='confirm password', widget=forms.PasswordInput(attrs={'class': 'form-control'},render_value=True))
    class Meta:
        model = User
        fields = ('name', 'email', 'password', 'confirm_password')
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.TextInput(attrs={'class': 'form-control'}),
            'password': forms.PasswordInput(attrs={'class': 'form-control'}, render_value=True),
        }
    def clean_password(self):
        pwd = self.cleaned_data.get('password')
        return md5(pwd)
    def clean_confirm_password(self):
        pwd = self.cleaned_data.get('password')
        confirm = md5(self.cleaned_data.get('confirm_password'))
        #print(self.cleaned_data)
        if confirm != pwd:
            raise ValidationError('two passwords are not the same')
        return confirm
def register(request):
    if request.method == "GET":
        form = registerform()
        return render(request, 'register.html', {'form': form})
    form = registerform(data=request.POST)
    print(form)
    if form.is_valid():
        form.save()
        return redirect('http://127.0.0.1:8000/login/')
    else:

        return render(request, 'register.html', {'form': form})
        #models.Userinfo.objects.create()


def logout(request):

    request.session.clear()
    return redirect('http://127.0.0.1:8000/login/')
'''def login(request):
    msg = {
        'site_title': "Sec-tools",
        'site_header': "Sec-tools 登录",
        'error': '',
        'color': 'transparent',
    }
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is None:
            msg['error'] = "用户名或密码错误！"
            msg['color'] = "#fef0f0"
        else:
            Login(request, user)
            return redirect("/index")
        # print(user)
        # print(msg)
    return render(request, "login_.html", msg)


def register(request):
    # 只有当请求为 POST 时，才表示用户提交了注册信息
    if request.method == 'POST':
        # request.POST 是一个类字典数据结构，记录了用户提交的注册信息
        # 这里提交的就是用户名（username）、密码（password）、邮箱（email）
        # 用这些数据实例化一个用户注册表单
        form = RegisterForm(request.POST)

        # 验证数据的合法性
        if form.is_valid():
            # 如果提交数据合法，调用表单的 save 方法将用户数据保存到数据库
            form.save()
            # 注册成功，跳转回首页
            return redirect('/login/')
    else:
        # 请求不是 POST，表明用户正在访问注册页面，展示一个空的注册表单给用户
        form = RegisterForm()

    # 渲染模板
    # 如果用户正在访问注册页面，则渲染的是一个空的注册表单
    # 如果用户通过表单提交注册信息，但是数据验证不合法，则渲染的是一个带有错误信息的表单
    return render(request, 'register.html', context={'form': form})


def login_out(request):
    logout(request)  # 注销
    return redirect("/index")  # 页面跳转
'''

