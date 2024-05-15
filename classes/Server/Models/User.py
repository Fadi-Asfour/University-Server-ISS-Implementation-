# create a user object

class User:
    def __init__(self, id, name, password, role, phone_number, mobile_number, national_num, address, public_key,  sk):
        self.id = id
        self.name = name
        self.password = password
        self.public_key = public_key
        self.role = role
        self.phone_number = phone_number
        self.mobile_number = mobile_number
        self.address = address
        self.national_num = national_num
        self.sk = sk
