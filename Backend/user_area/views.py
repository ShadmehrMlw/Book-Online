
import re, datetime
from rest_framework.views import APIView
from user_area.authentication import get_user_by_token
from user_area.functions import CsrfExemptSessionAuthentication, get_user_info,create_hash_token,create_otp_code
from rest_framework.authentication import BasicAuthentication 
from user_area.models import OtpCode, Province, Role,City, User
from user_area.serializers import ProvinceSerialize, RoleSerializer,CitySerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from .permissions import AllowAnyUser, IsAuthenticatedUser
from rest_framework import status
from .authentication import create_refresh_token, decode_refresh_token, get_user_by_token, set_cookie_for_user
from django.contrib.auth.models import update_last_login
from django.utils.timezone import utc, now, timedelta
from rest_framework.exceptions import PermissionDenied


#? check role for user
class RoleView(APIView):
	"""
		show all roles for user
	"""
	permission_classes = [AllowAnyUser]
	def get(self, request):
		roles = Role.objects.all()
		serializer = RoleSerializer(roles, many=True)
		return Response(serializer.data)
		

class CityView(APIView):
	permission_classes = [AllowAnyUser]

	def get(self, request):
		city = City.objects.all()
		serializer = CitySerializer(city, many = True)
		return Response(serializer.data)


class ProvinceView(APIView):
	permission_classes = [AllowAnyUser]

	def get(self, request):
		provinces = Province.objects.all()
		serializer = ProvinceSerialize(provinces, many = True)
		return Response(serializer.data)


class UserView(APIView):
	"""
		check user if user login
		check user info
	"""
	permission_classes = [IsAuthenticatedUser]
	authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)
	def get(self , request):
		user = get_user_by_token(request)
		if user:
			return Response({
				'data':get_user_info(user)
			})
		else:
			return Response({'detail': 'کاربری یافت نشد', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)


#? First step
class AuthenticatedView(APIView):
	"""
		register user and send otp code and to check user is registered or phone is exists or not
	"""
	permission_classes = [AllowAnyUser]
	authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)
	
	def get(self, request):
		return Response({'detail': 'درخواست "GET" مجاز نیست.'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

	def post(self, request):
		phone = request.data.get('phone')

		# is_login = False

		# user= User.objects.filter(phone=phone).first()

		# if user:
		# 	return Response({'detail': 'شماره تلفن وارد شده در سیستم موجود است', 'status':status.HTTP_200_OK}, status=status.HTTP_200_OK)

		# if len(phone) != 11:
		# 	return Response({'detail': 'شماره تلفن وارد شده صحیح نیست', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

		# # Create hash code for phone number
		# hash_code = create_hash_token()
	
		# create_otp_code(request, phone, hash_code)
		# print(request)
		
		# return Response({"is_login": is_login, 'detail': 'کد تایید برای شما ارسال شد', 'token': hash_code,'status':status.HTTP_200_OK}, status=status.HTTP_200_OK)

				# اصلاح: تغییر نام متغیر `is_login` به `is_registered` برای واضحی
		is_registered = False

		# اصلاح: استفاده از `exists()` برای بررسی وجود کاربر با شماره تلفن
		if User.objects.filter(phone=phone).exists():
			return Response({'detail': 'شماره تلفن وارد شده در سیستم موجود است', 'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)

		if len(phone) != 11:
			return Response({'detail': 'شماره تلفن وارد شده صحیح نیست', 'status': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

		# اصلاح: تغییر نام متغیر `hash_code` به `otp_token` برای واضحی
		otp_token = create_hash_token()
		create_otp_code(request, phone, otp_token)
		
		return Response({"is_registered": is_registered, 'detail': 'کد تایید برای شما ارسال شد', 'token': otp_token}, status=status.HTTP_200_OK)


#? Second step of login check phone number
class CheckPhoneView(APIView):
	"""
		check if user exist (send otp code) otherwise say phone is not in database
		check if user exist and has password
		check if user rejected or not
	"""
	permission_classes = [AllowAnyUser, ]
	authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

	def post(self, request):
		phone = request.data.get('phone')
		is_login = False
		has_password = False
		is_admin = False
	
		if not phone:
			return Response({'detail': 'لطفا شماره تماس را وارد کنید.', 'status': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
		
		if len(phone) != 11:
			return Response({'detail': 'شماره تلفن وارد شده صحیح نیست', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

		regex = re.compile(r'^09\d{9}$')
		if not regex.match(phone):
			return Response({'detail': 'شماره تلفن وارد شده صحیح نیست', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
		
		user= User.objects.filter(phone=phone).first()
		
		if user:
			is_login = True
			if user.status == -1:
				return Response({'detail': 'حساب کاربری شما مسدود شده است', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

			if user.password:
				if user.role.name == 'admin':
					is_admin = True
				has_password = True
				return Response({"is_login": is_login, 'is_admin': is_admin, "has_password":has_password, 'detail': 'پسورد خود را وارد کنید', 'status':status.HTTP_200_OK}, status=status.HTTP_200_OK)
	

			hash_code = create_hash_token()
			create_otp_code(request, phone, hash_code)
			return Response({'is_login':is_login, 'is_admin': is_admin, 'has_password':has_password , 'token': hash_code, 'detail': 'کد تایید برای شما ارسال شد', 'status':status.HTTP_200_OK}, status=status.HTTP_200_OK)
		
		return Response({'is_login':is_login, 'is_admin': is_admin, 'has_password':has_password, 'detail': 'شماره تلفن وارد شده در سیستم موجود نیست', 'status':status.HTTP_200_OK}, status=status.HTTP_200_OK)


#? Verify code 
class VerifyCodeView(APIView):
	"""
		Verify code for register
		Verify code for login
		Verify code for reset password
	"""
	permission_classes = [AllowAnyUser]
	authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)
	
	def post(self, request):
		phone = request.data.get('phone')#done
		token = request.data.get('token') #done
		code = request.data.get('code') #done

		
	
		if not phone:
			return Response({'detail': 'لطفا شماره تلفن را وارد کنید', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

		if not code:
			return Response({'detail': 'لطفا کد تایید را وارد کنید', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
		
		check_code = OtpCode.objects.filter(phone=phone, token=token, code=code).first()
		print(check_code, "code taeed are or not?")
		if not check_code:
			return Response({'detail': 'کد تایید نامعتبر است', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
		
		if not check_code.code:
			return Response({'detail': 'کد تاییدی برای شما ارسال نشده است', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
		
		user = User.objects.filter(phone=phone).first()

		if user:
			if check_code.code == int(code):
				
				check_code.delete()
				update_last_login(None, user)
				refresh_token = create_refresh_token(user.id,  user.phone)
				response = set_cookie_for_user(request, refresh_token)
				response.data = {
					'detail': 'یوزر با موفقیت وارد شد',
					'status':status.HTTP_200_OK,
				}
				return response
			else:
				return Response({'detail': 'کد تایید صحیح نیست', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
	

		expire_date = check_code.request_date
		expire_date = expire_date + timedelta(minutes=2)

		if expire_date < datetime.datetime.utcnow().replace(tzinfo=utc):
			check_code.delete()
			return Response({'detail': 'کد تایید منقضی شده است', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

		if check_code.code == int(code):
			
			user = User.objects.create(
				phone=phone, 
				
				)
			check_code.delete()

			
			
		
			
			refresh_token = create_refresh_token(user.id, phone)
			response = set_cookie_for_user(request, refresh_token)
			response.data = {
				'message': 'ثبت نام با موفقیت انجام شد',
				'status':status.HTTP_200_OK,
			}
			return response

		return Response({'detail': 'کد تایید نامعتبر است', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)


#? logout user
class LogoutView(APIView):
	"""logout user and delete cookie"""
	permission_classes = [IsAuthenticatedUser]
	authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

	def post(self, request):
		response = Response()
		response.delete_cookie('Authorization') #!TODO domain=current_site (this is for production)
		response.data = {
			'message': 'خروج با موفقیت انجام شد',
			'status':status.HTTP_200_OK,
		}
		return response

	def permission_denied(self, request, message=None, code=None):
		raise PermissionDenied(message)


#? Check Password 
class CheckPasswordView(APIView):
	"""check password if user save password"""
	permission_classes = [AllowAnyUser]
	authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

	def post(self, request):
		phone = request.data.get('phone')
		password = request.data.get('password')

		if not phone:
			return Response({'detail': 'لطفا شماره تلفن را وارد کنید', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
			
		if not password:
			return Response({'detail': 'لطفا رمز عبور را وارد کنید', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
		
		user = User.objects.filter(phone=phone).first()
		if not user:
			return Response({'detail': 'کاربری با این شماره وجود ندارد', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
		
		if not user.check_password(password):
			return Response({'detail': 'رمز عبور اشتباه است', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

		if user.check_password(password):
			update_last_login(None, user)
			if user.role.name == "admin":
				refresh_token = create_refresh_token(user.id, user.phone)
			else:
				refresh_token = create_refresh_token(user.id, user.phone)
			refresh_token = decode_refresh_token(refresh_token)
			response = set_cookie_for_user(request, refresh_token)
			response.data = {
				'detail': 'یوزر با موفقیت وارد شد',
				'status':status.HTTP_200_OK,
			}
			return response


#? Forgot Password
class ForgotPasswordView(APIView):
	"""
		forgot password if user forget password
	"""
	permission_classes = [AllowAnyUser]
	authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

	def post(self, request):
		phone = request.data.get('phone')
		if not phone:
			return Response({'detail': 'لطفا شماره تلفن را وارد کنید', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
		
		user = User.objects.filter(phone=phone).first()
		if not user:
			return Response({'detail': 'کاربری با این شماره وجود ندارد', 'status':status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
		
		if user:
			hash_code = create_hash_token()
			create_otp_code(request, phone, hash_code)
			return Response({'detail': 'کد تایید برای شما ارسال شد', 'token': hash_code,'status':status.HTTP_200_OK}, status=status.HTTP_200_OK)
