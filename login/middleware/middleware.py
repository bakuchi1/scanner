from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import render, redirect,HttpResponse
class AuthMiddleware(MiddlewareMixin):

    def process_request(self, request):
        if request.path_info == '/login/' or 'register/':
            return

        info_dict = request.session.get('info')

        if info_dict:
            return
        return redirect('http://127.0.0.1:8000/login/')