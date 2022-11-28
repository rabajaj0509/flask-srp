import srp
from client import ClientAuth as ca

def AuthenticationFailed():
    return "AuthenticationFailed"

class ServerAuth:
    def __init__(self, usr, s, B, HAMK):
        self.usr = usr
        self.s = s
        self.B = B
        self.HAMK = HAMK

    def process_challenge(self):
        M = self.usr.process_challenge(self.s, self.B)
        if M is None:
            print("==> Failed at process_challenge")
        print("==> S = {}, B = {}, M = {}".format(self.s, self.B, M))
        return M

    def verify_session(self):
        self.usr.verify_session(self.HAMK)
      