import jwt
import time
from settings import CLIENTS, ISSUER, JWT_LIFE_SPAN, JWT_INTITAL, PUBLIC
import lungo
from flask import current_app as app


def get_certificate_key(client_id, cert='private'):
    certificate = None
    file_name = CLIENTS.get(client_id).get('certificate')
    with open('certs/{}-{}.pem'.format(file_name, cert), 'rb') as f:
        certificate = f.read()

    return certificate


def generate_state(payload, expiry=JWT_LIFE_SPAN):
    """
    :return:
    """
    data = payload.copy()
    data['iss'] = ISSUER
    data['exp'] = time.time() + expiry
    data['iat'] = time.time()
    state = jwt.encode(data, key=get_certificate_key(data.get('client_id', '')), algorithm='RS256').decode()

    return state


def decode_state(state, verify=True):
    try:
        claims = jwt.decode(state, verify=False)
        if verify is True:
            try:
                jwt.decode(jwt=state,
                           key=get_certificate_key(claims.get('client_id'), cert='public'),
                           issuer=ISSUER,
                           algorithms=['RS256'], verify=True)
            except (jwt.exceptions.InvalidTokenError,
                    jwt.exceptions.InvalidSignatureError,
                    jwt.exceptions.InvalidIssuerError,
                    jwt.exceptions.ExpiredSignatureError) as e:
                return {}

        return claims

    except (jwt.exceptions.InvalidTokenError,
            jwt.exceptions.InvalidSignatureError,
            jwt.exceptions.InvalidIssuerError,
            jwt.exceptions.ExpiredSignatureError):
        app.logger.exception('Could not decode state')

    return None


class Auth:
    def __init__(self, client_id):

        self.person_id = None
        self.full_name = None
        self.first_name = None
        self.last_name = None
        self.email = None
        self.activities = []
        self.melwin_id = None

        self.client = None
        self.client_id = client_id
        self._set_client()
        self.decoded_token = None

    def _set_client(self):
        self.client = CLIENTS.get(self.client_id, None)

    def _get_client(self):
        return CLIENTS.get(self.client_id, {})

    def allow_non_members(self):
        if PUBLIC in CLIENTS[self.client_id]['activities']:
            return True

        return False

    def verify_activity(self) -> bool:
        """Check that person has activity according to client access"""

        # If ALL allowed


        act_status, self.activities = lungo.get_activities(self.person_id)


        if act_status is True:

            if any(x in self.activities for x in CLIENTS[self.client_id]['activities']):
                return True

        if self.allow_non_members() is True:
            return True

        return False

    def get_melwin_id(self, person_id):
        try:
            melwin_status, self.melwin_id = lungo.get_melwin_id(person_id)
        except:
            self.melwin_id = None

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

    def _get_ws_person(self, person_id):
        from oidc import OIDC
        oidc = OIDC()
        return oidc.get_ws_person(self.person_id)

    def generate_access_token(self, expiry=JWT_LIFE_SPAN):
        """
        “exp” (Expiration Time) Claim
        “nbf” (Not Before Time) Claim
        “iss” (Issuer) Claim
        “aud” (Audience) Claim
        “iat” (Issued At) Claim

        :return:
        """

        member = True
        # Members return True (in membership api)
        _status, self.first_name, self.last_name, self.email = lungo.get_lungo_person(self.person_id)

        if _status is False:
            # If non-members is allowed:
            if self.allow_non_members() is True:
                _, self.first_name, self.last_name, self.email = self._get_ws_person(self.person_id)
                member = False

        payload = {
            "iss": ISSUER,
            "exp": time.time() + expiry,
            "iat": time.time(),
            "person_id": self.person_id,
            "melwin_id": self.melwin_id,
            "client_id": self.client_id,
            "full_name": self.first_name + ' ' + self.last_name,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "member": member,
            "activities": self.activities
            # "scope": self.client.get('scope', 'read')
        }

        access_token = jwt.encode(payload,
                                  get_certificate_key(client_id=self.client_id, cert='private'),
                                  algorithm='RS256').decode()

        return access_token

    def verify_token(self, token):
        try:
            self.decoded_token = jwt.decode(token,
                                            get_certificate_key(client_id=self.client_id, cert='public'),
                                            issuer=ISSUER,
                                            algorithms=['RS256'])
            return True

        except (jwt.exceptions.InvalidTokenError,
                jwt.exceptions.InvalidSignatureError,
                jwt.exceptions.InvalidIssuerError,
                jwt.exceptions.ExpiredSignatureError):
            app.logger.exception('Could not verify token')
        return False

    def get_client_id_from_token(self, token):
        try:
            claims = jwt.decode(token, verify=False)

            return claims.get('client_id')

        except (jwt.exceptions.InvalidTokenError,
                jwt.exceptions.InvalidSignatureError,
                jwt.exceptions.InvalidIssuerError,
                jwt.exceptions.ExpiredSignatureError):
            app.logger.exception('Could not get id from token')

        return None

    def refresh_token(self, token):

        try:
            decoded_token = jwt.decode(token,
                                       get_certificate_key(client_id=self.client_id, cert='public'),
                                       options={'verify_exp': False},
                                       issuer=ISSUER,
                                       algorithms=['RS256'])

            self.person_id = decoded_token.get('person_id', None)
            return self.generate_access_token()

        except (jwt.exceptions.InvalidTokenError,
                jwt.exceptions.InvalidSignatureError,
                jwt.exceptions.InvalidIssuerError,
                jwt.exceptions.ExpiredSignatureError):
            app.logger.exception('Could not refresh token')

        return False

    def get_user_id(self, token):
        try:
            decoded_token = jwt.decode(token,
                                       get_certificate_key(client_id=self.client_id, cert='public'),
                                       options={'verify_exp': False},
                                       issuer=ISSUER,
                                       algorithms=['RS256'])
            return int(decoded_token.get('id', None))

        except (jwt.exceptions.InvalidTokenError,
                jwt.exceptions.InvalidSignatureError,
                jwt.exceptions.InvalidIssuerError,
                jwt.exceptions.ExpiredSignatureError):
            app.logger.exception('Could not get user id from token')

        return False
