import jwt
import time
from nif_tools import Passbuy
import requests
from settings import clients, RETRY_USER
import lungo
from bs4 import BeautifulSoup

ISSUER = 'nlf-auth-server'
JWT_LIFE_SPAN = 3600
JWT_INTITAL = 5 * 60
REALM = 'minidrett'

authorization_codes = {}


def _is_nif_maintanance():
    """Check if maintanance mode

    NIF web (KA/MI/SA) gives normal http 200, need to check title
    Also: re.search('(?<=<title>).+?(?=</title>)', mytext, re.DOTALL).group().strip()

    :returns boolean is_maintanance:
    """
    try:
        r = requests.get('https://{}.nif.no'.format(REALM))

        if r.status_code == 200:
            html = BeautifulSoup(r.text, 'lxml')
            if html.title.text.strip() == 'Vedlikehold':
                return True
            elif html.title.text.strip().startswith('Release'):
                return True
    except:
        return True

    return False


class Auth:
    def __init__(self, client_id):

        self.person_id = None
        self.melwin_id = None
        self.client = None
        self.client_id = client_id
        self._set_client()
        self.decoded_token = None

    def _set_client(self):
        self.client = clients.get(self.client_id, None)

        # if self.client is None:
        #    raise Exception

    def _get_client(self):
        return clients.get(self.client_id, {})

    def _get_key(self, cert='private'):
        certificate = None
        with open('certs/{}-{}.pem'.format(self._get_client().get('certificate'), cert), 'rb') as f:
            certificate = f.read()

        return certificate

    def _retry_login(self):
        try:
            pb = Passbuy(RETRY_USER['username'], RETRY_USER['password'], REALM)
            pb.login()
        except:
            pass

    def authenticate_user_credentials(self, username, password, client_id):

        pb = Passbuy(username.strip(), password.strip(), REALM)

        try:
            status, self.person_id, fed = pb.login()

            if self.person_id > 0:

                melwin_status, self.melwin_id = lungo.get_melwin_id(self.person_id)

                if melwin_status is False:
                    pass

                act_status, activities = lungo.get_activities(self.person_id)

                if act_status is True:

                    if any(x in activities for x in clients[client_id]['activities']):
                        return True

            else:
                pass

        except AttributeError as e:
            pass
        except Exception as e:
            pass

        # Do not need for new login
        # self._retry_login()
        return False

    def verify_redirect_uri(self, redirect_uri):

        if self.client is not None:
            if redirect_uri.startswith(self.client.get('redirect_uri', None)):
                return True

        return False

    def verify_scope(self, scope):
        if self.client is not None:
            if scope == self.client.get('scope', None):
                return True

        return False

    def verify_response_type(self, reponse_type):
        if self.client is not None:
            if reponse_type == self.client.get('response_type', None):
                return True

        return False

    def verify_client_secret(self, client_secret):
        if self.client is not None:
            if client_secret == self.client.get('client_secret', None):
                return True

        return False

    def generate_access_token(self, expiry=JWT_LIFE_SPAN):
        """
        “exp” (Expiration Time) Claim
        “nbf” (Not Before Time) Claim
        “iss” (Issuer) Claim
        “aud” (Audience) Claim
        “iat” (Issued At) Claim

        :return:
        """
        payload = {
            "iss": ISSUER,
            "exp": time.time() + expiry,
            "iat": time.time(),
            "person_id": self.person_id,
            "melwin_id": self.melwin_id,
            "client_id": self.client_id,
            # "scope": self.client.get('scope', 'read')
        }

        access_token = jwt.encode(payload, self._get_key('private'), algorithm='RS256').decode()

        return access_token

    def verify_token(self, token):
        try:
            self.decoded_token = jwt.decode(token, self._get_key('public'), issuer=ISSUER, algorithm='HS256')
            return True

        except (jwt.exceptions.InvalidTokenError,
                jwt.exceptions.InvalidSignatureError,
                jwt.exceptions.InvalidIssuerError,
                jwt.exceptions.ExpiredSignatureError):
            return False

    def get_client_id_from_token(self, token):
        try:
            claims = jwt.decode(token, verify=False)

            return claims.get('client_id')

        except (jwt.exceptions.InvalidTokenError,
                jwt.exceptions.InvalidSignatureError,
                jwt.exceptions.InvalidIssuerError,
                jwt.exceptions.ExpiredSignatureError):
            return None

    def refresh_token(self, token):

        try:
            decoded_token = jwt.decode(token,
                                       self._get_key('public'),
                                       options={'verify_exp': False},
                                       issuer=ISSUER,
                                       algorithm='HS256')

            self.person_id = decoded_token.get('person_id', None)
            return self.generate_access_token()

        except (jwt.exceptions.InvalidTokenError,
                jwt.exceptions.InvalidSignatureError,
                jwt.exceptions.InvalidIssuerError,
                jwt.exceptions.ExpiredSignatureError):
            return False

    def get_user_id(self, token):
        try:
            decoded_token = jwt.decode(token, self._get_key('public'), options={'verify_exp': False}, issuer=ISSUER,
                                       algorithm='HS256')
            return int(decoded_token.get('id', None))

        except (jwt.exceptions.InvalidTokenError,
                jwt.exceptions.InvalidSignatureError,
                jwt.exceptions.InvalidIssuerError,
                jwt.exceptions.ExpiredSignatureError):
            return False
