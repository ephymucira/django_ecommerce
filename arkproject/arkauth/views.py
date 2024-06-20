from django.shortcuts import render,HttpResponse,redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.views.generic import View 
# from .models import Contact,Blogs
from django.core.mail import send_mail
from django.conf import settings
from django.core import mail
from django.core.mail.message import EmailMessage

#To activate user account
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import NoReverseMatch,reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str,DjangoUnicodeDecodeError

#getting tokens from utils.py
from .utils import EmailThread
from .tokens import generate_token

#Emails
from django.core.mail import send_mail,EmailMultiAlternatives
from django.core.mail import BadHeaderError, send_mail
from django.core import mail
from django.conf import settings

#reset password generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator

import logging
#Add logging to verify the URL pattern and view are being hit

logger = logging.getLogger(__name__)




# Create your views here.
def signup(request):
    if request.method == "POST":  
        username = request.POST['username']  
        email = request.POST['email']     
        password = request.POST['pass1']     
        confirm_password = request.POST['pass2']  
        if password != confirm_password:
            messages.warning(request, "Passwords do not match!")
            return render(request,'auth/signup.html')
        
        try:
            if User.objects.get(username=username):
                messages.warning(request,"Username is taken!")
                return render(request,"auth/signup.html")
        except Exception as identifier:
            pass    
        
        try:
            if User.objects.get(email=email):
                messages.warning(request,"Email is taken!")
                return render(request,"auth/signup.html")
        except Exception as identifier:
            pass   
        
        user = User.objects.create_user(username,email,password)
        user.is_active = False
        user.save()
        current_site = get_current_site(request)
        email_subject = "Activate your account"
        message = render_to_string('auth/activate.html',{
            'user':user,
            'domain':'127.0.0.1:8000',
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)
        })
        
        email_message = EmailMessage(email_subject, message,settings.
                                     EMAIL_HOST_USER,[email],)
        EmailThread(email_message).start()
        messages.info(request,"Activate your account by clicking the link on your email")
        return redirect('/arkauth/login')
        
         
    return render(request,'auth/signup.html')


class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user  is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account activated Successfully!")
            return redirect('handlelogin')
        return render(request,'auth/activatefail.html')
            




def handlelogin(request):
    if request.method == "POST":
        username = request.POST.get('username')
        userpassword = request.POST.get('pass1')
        
        # Validate email and password
        if not username or not userpassword:
            messages.error(request, "username and password are required.")
            return redirect('/arkauth/login')
        
        # Debug statements
        # print(f"Authenticating user with username: {username}")
        
        # Attempt to authenticate the user
        myuser = authenticate(request, username=username, password=userpassword)  # Using 'username' for email in custom backend
        
        if myuser is not None:
            login(request, myuser)
            messages.success(request, f"Login success! Welcome {myuser.username}")
            return redirect('/',{'username': myuser.username})  # Redirect to the homepage or another appropriate page
        else:
            messages.error(request, "Invalid username or password!")
            return redirect('/arkauth/login')
    return render(request, 'auth/login.html')

def handlelogout(request):
    logout(request)
    messages.success(request, "Logout successful !")
    return redirect("/arkauth/login")
    
class RequestResetEmailView(View):
    def get(self,request):
        return render(request,"auth/request-email-reset.html")

    def post(self, request):
        email = request.POST['email']
        user = User.objects.filter(email=email)
        
        if user.exists():
            current_site = get_current_site(request)
            email_subject = '[Reset your Password]'
            message = render_to_string('auth/reset-user-password.html',
                                       {
                                           'domain':'127.0.0.1:8000',
                                           'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
                                           'token':PasswordResetTokenGenerator().make_token(user[0])
                                       })
            email_message = EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
            EmailThread(email_message).start()
            
            messages.info(request, "We have sent you an email with instructions on how to reset your password")
            return render(request, 'auth/request-email-reset.html')
 
class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        logger.debug(f"GET request received with uidb64: {uidb64}, token: {token}")
        context = {
            'uidb64': uidb64,
            'token': token
        }
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password Reset Link is Invalid!")
                return render(request, 'auth/request-email-reset.html')
        except DjangoUnicodeDecodeError:
            messages.error(request, "Invalid link!")
            return render(request, 'auth/request-email-reset.html')
        
        return render(request, 'auth/set-new-password.html', context) 

    def post(self, request, uidb64, token):
        logger.debug(f"POST request received with uidb64: {uidb64}, token: {token}")
        context = {
            'uidb64': uidb64,
            'token': token
        }
        password = request.POST.get('pass1')     
        confirm_password = request.POST.get('pass2')
        
        if password != confirm_password:
            messages.warning(request, "Passwords do not match!")
            return render(request, 'auth/set-new-password.html', context)
        
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password Reset Link is Invalid")
                return render(request, 'auth/request-email-reset.html')

            user.set_password(password)
            user.save()
            messages.success(request, "Password reset successful! Login with new password")
            return redirect('handlelogin')
        except DjangoUnicodeDecodeError:
            messages.error(request, "Something went wrong!")
            return render(request, 'auth/set-new-password.html', context)