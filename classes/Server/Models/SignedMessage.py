# create a aigned message object
# import json


class SignedMessage:
    def __init__(self, publicKey, data_path, sig_path):
        self.publicKey = publicKey
        self.data_path = data_path
        self.sig_path = sig_path

    # def toJSON(self):
    #     return json.dumps(self, default=lambda o: o.__dict__,
    #                       sort_keys=True, indent=4)
