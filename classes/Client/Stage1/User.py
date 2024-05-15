class User:

    def __init__(self, username, password, key_value=None, role=None):
        self.username = username
        self.password = password
        self.key_value = key_value
        self.role = role
