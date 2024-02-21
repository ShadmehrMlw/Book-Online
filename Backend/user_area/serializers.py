from rest_framework import serializers
from user_area.models import Province, Role, City



class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = "__all__"

class ProvinceSerialize(serializers.ModelSerializer):
    city_province = serializers.StringRelatedField(many=True)
    class Meta:
        model = Province
        fields = "__all__"


class CitySerializer(serializers.ModelSerializer):
    province = ProvinceSerialize(read_only = True, many=False)
    class Meta:
        model = City
        fields = "__all__"







