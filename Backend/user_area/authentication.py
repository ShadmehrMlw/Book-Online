from jwt.exceptions import InvalidSignatureError, DecodeError, ExpiredSignatureError
from django.conf import settings
from rest_framework.response import Response
from rest_framework import exceptions

import jwt, datetime

from .models import User

 
#? Create token
def create_refresh_token(id,  phone):
    return jwt.encode({
        'phone': phone,
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=90),
    }, settings.SECRET_KEY, algorithm='HS256')



#? Decode refresh token
def decode_refresh_token(token):
    try:
        payload = jwt.decode(token,settings.SECRET_KEY, algorithms='HS256')
        return payload
    except InvalidSignatureError:
        raise exceptions.AuthenticationFailed('Signature verification failed')
    except (DecodeError, ExpiredSignatureError):
        raise exceptions.AuthenticationFailed('Invalid token')



#? Set cookie
def set_cookie_for_user(request, refresh_token):
    response = Response()
    response.set_cookie(key='Authorization', value=refresh_token, httponly=True, samesite='None', expires=datetime.datetime.utcnow() + datetime.timedelta(days=91))
    return response



# # #? Get user by jwt token
def get_user_by_token(request):
    token = request.COOKIES.get('Authorization')
    if token:
        bytes_token=token.strip("b'").encode()
        if bytes_token:
            refresh_decode = decode_refresh_token(bytes_token)
            user = User.objects.filter(phone=refresh_decode['phone']).first()
            return user
    return None

  
