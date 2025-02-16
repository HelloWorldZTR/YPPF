from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib import auth
from django.db import transaction

from wx.serializers import LoginSerializer, VerifySerializer
from wx.config import miniAPP_config as CONFIG
from generic.models import User
from app.models import Organization
from app.utils import update_related_account_in_session
import utils.models.query as SQ
from utils.health_check import db_connection_healthy
from utils.views import SecureView, SecureTemplateView
from utils.http.dependency import HttpRequest, HttpResponse, UserRequest
from utils.global_messages import succeed
from typing import cast
import requests


# Create your views here.

'''
微信小程序登录
'''
class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)
        code = request.data.get('code')
        app_id = CONFIG.app_id
        app_secret = CONFIG.app_secret
        res = requests.get(f'https://api.weixin.qq.com/sns/jscode2session?appid={app_id}&secret={app_secret}&js_code={code}&grant_type=authorization_code')

        error_code = res.json().get('errcode')
        error_msg = res.json().get('errmsg')
        if error_code:
            return Response({'error_code': error_code, 'error_msg': error_msg}, status=400)
        else:
            session_key = res.json().get('session_key')
            openid = res.json().get('openid')
            
            # print('session_key: ', session_key)
            # print('openid: ', openid)
            # 存入Session
            request.session['openid'] = openid
            request.session['session_key'] = session_key
            print('Saved to session')
            # 是否已经绑定
            user = User.objects.filter(openid=openid).first()
            if user:
                return Response({
                    'openid': openid,
                    'session_key':session_key
                },status=200)
            else:
                return Response({
                    'openid': openid,
                    'session_key': session_key,
                    'bind': True # 需要绑定
                }, status=200)


class BindView(SecureTemplateView):
    login_required = False
    template_name = 'wx/bind.html'

    def dispatch_prepare(self, method: str) -> SecureView.HandlerType:
        match method:
            case 'get':
                return (self.user_get
                        if self.request.user.is_authenticated else
                        self.visitor_get)
            case 'post':
                return self.prepare_bind()
            case _:
                return self.default_prepare(method)

    def visitor_get(self) -> HttpResponse:
        # Modify password
        # Seems that after modification, log out by default?
        if self.request.GET.get('modinfo') is not None:
            succeed("修改密码成功!", self.extra_context)
        return self.render()

    def user_get(self) -> HttpResponse:
        self.request = cast(UserRequest, self.request)
        # Special user
        self.valid_user_check(self.request.user)

        # Logout
        if self.request.GET.get('is_logout') is not None:
            return self.redirect('logout')

        return self.redirect('welcome')

    def valid_user_check(self, user: User):
        # Special user
        if not user.is_valid():
            self.permission_denied(
                f'“{user.get_full_name()}”不存在成长档案，您可以登录其他账号'
            )

    def ip_check(self) -> None:
        # Prevent bug report
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for and x_forwarded_for.split(',')[0] == '127.0.0.1':
            self.permission_denied('请使用域名访问')

    def prepare_bind(self) -> SecureView.HandlerType:
        self.ip_check()
        assert 'username' in self.request.POST
        assert 'password' in self.request.POST
        assert 'openid' in self.request.session

        _user = self.request.user
        assert not _user.is_authenticated or not cast(User, _user).is_valid()
        username = self.request.POST['username']
        # Check whether username exists or not
        if not SQ.sfilter(User.username, username).exists():
            # Allow org to login with orgname
            org = SQ.sfilter(Organization.oname, username).first()
            if org is None:
                return self.wrong('用户名不存在')
            username = cast(Organization, org).get_user().username
        self.username = username
        self.password = self.request.POST['password']
        self.openid = self.request.session.get('openid')
        return self.bind        

    def bind(self) -> HttpResponse:
        # Try login
        userinfo = auth.authenticate(username=self.username, password=self.password)
        if userinfo is None:
            return self.wrong('密码错误')

        # special user
        auth.login(self.request, userinfo)
        self.request = cast(UserRequest, self.request)
        self.valid_user_check(self.request.user)

        # with transaction.atomic():
        #     user = self.request.user
        #     user.openid = self.openid
        #     user.save()

        # first time login
        if self.request.user.is_newuser:
            return self.redirect('modpw')

        # Related account
        # When login as np, related org accout is also available
        update_related_account_in_session(self.request, self.username)

        return self.redirect("wxbindcallback")

def wxLogInCallbackView(request: HttpRequest) -> HttpResponse:
    return render(request, 'wx/callback.html')


