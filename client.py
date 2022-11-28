import srp

def AuthenticationFailed():
    return "AuthenticationFailed"

class ClientAuth:
    def __init__(self, testuser, testpassword, M, svr):
        self.testuser = testuser
        self.testpassword = testpassword
        self.M = M
        self.svr = svr

    def client_send(self):
        salt, vkey = srp.create_salted_verification_key(self.testuser, self.testpassword)
        usr = srp.User(self.testuser, self.testpassword)
        uname, A = usr.start_authentication()
        svr = srp.Verifier(uname, salt, vkey, A)
        self.svr = svr
        s,B = svr.get_challenge()
        print("==> salt = {}, S = {}".format(salt, s))

        if s is None or B is None:
            print("==> Failed at client_send")
        
        """
        (<srp._pysrp.User at 0x7fba3ab4c590>,
        b'vq-\xea',
        b"@A\xd9u\xb7q\xd4 \x95\xf0\xb8\xb3\t\xc99\xc7\xa3\x91\x93L\xef\x1f\xa8|\xf6\xb4\x85gf\x18\x17X\x02*\x1b\x18,\x01!\xfdTEh\x80\xb4\x13\xd7\xb5\x13\xb8C\xb1i\n~\xc4{\xb9z%R\xd2y\xddC`\x9f\x9bQ\x04\xeb\xe2\x0c\x8c\x83\xc6\xb2\xbd\x95\x9f\x03\x10~\x82J V\t\x89\xdfovd\x1a\x04\xe2\\\xcb\x91\x07\xb2\x81\xa9l\xf3I\xd4ky\x11\xc8a\x87hu\xe2\tF\x9bk\xbf\x8aA\xa3\x855\xa9\xebc\x8b\x16\x94\xf8\xeb\x95\xe1\xe3\x9f\x1d\xac\x12\xad\x0c\xa2?N[\x14\x94\xa8\xd4\xf5\xdf*:\xab\x17}Z\x01\x9d\xab\x80\xf23\xd8U\x7f3\xad8~uX-\x82\xb1%B\xb1U\xc5f~L\xabC6\x8f\x1bS{KN\xf2e\x96\xb3\xa8f\xc4\xf1r\xfdk=\xbbch\xb5\x81i\x91Z\x00\xecV\xf6\x7f\x01L*`rv\xb1\x04`e\xf1\xdf\x8a\xa3h.s\t\xad\xf94\xe5{\xd25$\x0c\xa5&3\x04\xf6\xfd)z'/")
        """
        return (usr, s, B)
    
    def verify_session(self):
        print("==> M ka value ==>{}".format(self.M))
        HAMK = self.svr.verify_session(self.M)
        if HAMK is None:
            print("==> Failed at verify_session")
        return HAMK

