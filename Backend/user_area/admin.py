from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from django.contrib import admin
from .models import *
from .forms import UserCreationForm, UserChangeForm

class UserAdmin(BaseUserAdmin):
	form = UserChangeForm
	add_form = UserCreationForm
	list_display = ('phone', 'fullname','role', 'status', 'city')
	list_filter =  ('role',)
	fieldsets = (None, {'fields': ('fullname', 'password', 'city', 'phone', 'email', 'role', 'avatar', 'status')}),
	add_fieldsets = (None, {'fields': ('fullname' , 'phone', 'city', 'email', 'role', 'avatar', 'status', 'password1', 'password2')}),

	search_fields =  ('fullname', 'email')
	ordering = ('fullname',)

admin.site.unregister(Group)
admin.site.register(User, UserAdmin)





class OtpCodeAdmin(admin.ModelAdmin):
	list_display = ('phone', 'code', 'ip_address')
	list_filter =  ('phone',)
	readonly_fields = ('request_date',)
admin.site.register(OtpCode, OtpCodeAdmin)


class RoleAdmin(admin.ModelAdmin):
	list_display = ('name', 'display_name')
	list_filter =  ('name',)
	search_fields =  ('name',)
	ordering = ('name',)
admin.site.register(Role, RoleAdmin)


class ProvinceAdmin(admin.ModelAdmin):
	list_display = ('name', )
	list_filter =  ('name',)
	search_fields =  ('name',)
	ordering = ('name',)
admin.site.register(Province, ProvinceAdmin)


class CityAdmin(admin.ModelAdmin):
	list_display = ('name', 'province', 'slug')
	list_filter =  ('name',)
	search_fields =  ('name',)
	ordering = ('name',)
	prepopulated_fields = {'slug': ('name',)}
admin.site.register(City, CityAdmin)












