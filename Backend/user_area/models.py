from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models

from .managers import UserManager



class BaseModel(models.Model):
	"""
		This is a abstract model for all models need to have created_at and update_at
	"""
	created_at = models.DateTimeField(auto_now_add=True)
	update_at= models.DateTimeField(auto_now=True)

	class Meta:
		abstract = True
	

class Role(models.Model):
	"""
		- name: name of role
		- display_name: display name of role
		included roles are admin(id=1), banned(2), advisor(3),
		
	"""
	name = models.CharField(max_length=32)
	display_name = models.CharField(max_length=32)

	def __str__(self):
		return self.name


class Province(models.Model):
	"""
		- name: name of province in iran
	"""
	name = models.CharField(max_length=100)
	slug = models.SlugField(max_length=100)

	def __str__(self):
		return self.name


class City(models.Model):
	"""
		- name: name of city in iran
		- province: province of city
	"""
	name = models.CharField(max_length=100)
	slug = models.SlugField(max_length=100)
	province = models.ForeignKey(Province, on_delete=models.CASCADE, related_name='city_province', null=True, blank=True)
	

	def __str__(self):
		return self.name

	class Meta:
		verbose_name = 'City'
		verbose_name_plural = 'Cities'



class User(AbstractBaseUser, PermissionsMixin):
	"""
		a abstract model for all users
		get default avatar from media table
	"""
	STATUS = (
		(-1, 'blocked'),
		(0, 'deactive'),
		(1, 'active'),
	)
	fullname = models.CharField(max_length=255)
	phone = models.CharField(max_length=11, unique=True)
	city = models.ForeignKey(City, on_delete=models.DO_NOTHING, related_name='user_city', blank=True, null=True)
	role = models.ForeignKey(Role, on_delete=models.DO_NOTHING, related_name='user_role', blank=True, null=True)
	email = models.EmailField(max_length=255, null=True, blank=True)
	avatar = models.ImageField(upload_to="avatar", blank=True, null=True)
	status = models.IntegerField(choices=STATUS, default=1)

	objects = UserManager()

	USERNAME_FIELD = 'phone' # for authentication purposes
	REQUIRED_FIELDS = ['fullname', ] # just for createsuperuser

	

	def __str__(self):
		return f"{self.fullname} - {self.id}"

	def has_perm(self, perm, obj=None):
		return True

	def has_moduls_perms(self, app_label):
		return True

	@property
	def is_staff(self):
		return self.is_superuser



class OtpCode(models.Model):
	"""
		create code for sms verification
	"""
	phone = models.CharField(max_length=11)
	ip_address = models.CharField(max_length=255)
	code = models.PositiveIntegerField()
	token = models.CharField(max_length=255, null=True, blank=True)
	request_date = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return self.phone

