# create a register object


class Register:
    def __init__(self, userName, password, role, ID, public_key, key=None):
        self.userName = userName
        self.password = password
        self.role = role
        self.ID = ID
        self.public_key = public_key
        self.key = key
