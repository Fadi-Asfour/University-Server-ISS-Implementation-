# create a request object


class Request:
    def __init__(self, url, public_key, data):
        self.url = url
        self.public_key = public_key
        self.data = data
