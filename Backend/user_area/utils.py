from kavenegar import *


def send_otp_code(phone, code):
    try:
        api = KavenegarAPI(
            '4B756A656D7A48324A65516E5A6534552F6A49644446595A2F2F4B6B766E6E337A69417975345557622F453D')

        params = {
            'sender': '',  # optional
            'template': 'otp',
            'receptor': phone,  # multiple mobile number, split by comma
            'token': code,
            'type': 'sms'
        }
        api.verify_lookup(params)
    except APIException as e:
        print(e)
    except HTTPException as e:
        print(e)
