import jwt
import time
from settings import CLIENTS, ISSUER, JWT_LIFE_SPAN, PUBLIC, DO_NOT_VERIFY_ACTIVITY_FOR_PERSONS, DO_NOT_VERIFY_ORGS_FOR_PERSONS
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
    # data['aud'] = data.get('client_id', '')
    state = jwt.encode(data, key=get_certificate_key(data.get('client_id', '')), algorithm='RS256')

    return state


def decode_state(state, verify=True):
    try:
        claims = jwt.decode(state, verify=False, algorithms=['RS256'])
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

        if CLIENTS[self.client_id]['verify_activity'] is False:
            return True

        # If person allowed anyway:
        if self.person_id in DO_NOT_VERIFY_ACTIVITY_FOR_PERSONS:
            return True

        act_status, self.activities = lungo.get_activities(self.person_id)

        if act_status is True:

            if any(x in self.activities for x in CLIENTS[self.client_id]['activities']):
                return True

        # Allow ANY NIF member regardless of activity
        if self.allow_non_members() is True:
            return True

        return False

    def verify_org(self) -> bool:
        """Check that person has activity according to client access"""

        if CLIENTS[self.client_id]['verify_orgs'] is False:
            return True

        # If person allowed anyway:
        if self.person_id in DO_NOT_VERIFY_ORGS_FOR_PERSONS:
            return True

        status, self.orgs = lungo.get_orgs(self.person_id)

        if status is True:

            if any(x in self.orgs for x in CLIENTS[self.client_id]['orgs']):
                return True

        # Allow ANY NIF member regardless of org
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

    def _get_nif_api_person(self, person_id):
        from oidc import OIDC
        oidc = OIDC()
        return oidc.get_nif_api_person(self.person_id)

    def generate_access_token(self, expiry=JWT_LIFE_SPAN, state=None):
        """
        “exp” (Expiration Time) Claim
        “nbf” (Not Before Time) Claim
        “iss” (Issuer) Claim
        “aud” (Audience) Claim
        “iat” (Issued At) Claim

        :return:
        """

        # Members return True (in membership api)
        _status, self.first_name, self.last_name, self.email = lungo.get_lungo_person(self.person_id)

        if _status is False:
            # If non-members is allowed:
            if self.allow_non_members() is True:
                _, self.first_name, self.last_name, self.email = self._get_nif_api_person(self.person_id)

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
            "activities": self.activities,
            # "scope": self.client.get('scope', 'read')
        }  # "aud": self.client_id,

        if state is not None:
            payload['state'] = state

        access_token = jwt.encode(payload,
                                  get_certificate_key(client_id=self.client_id, cert='private'),
                                  algorithm='RS256')

        return access_token

    def generate_refresh_token(self, expiry=JWT_LIFE_SPAN):
        """
        :return:
        """
        payload = {
            "iss": ISSUER,
            "exp": time.time() + expiry,
            "iat": time.time(),
            "client_id": self.client_id
        }
        refresh_token = jwt.encode(payload,
                                   get_certificate_key(client_id=self.client_id, cert='private'),
                                   algorithm='RS256')

        return refresh_token

    def generate_id_token(self, expiry=JWT_LIFE_SPAN):
        """
        “exp” (Expiration Time) Claim
        “nbf” (Not Before Time) Claim
        “iss” (Issuer) Claim
        “aud” (Audience) Claim
        “iat” (Issued At) Claim

        :return:
        """

        # Members return True (in membership api)
        _status, self.first_name, self.last_name, self.email = lungo.get_lungo_person(self.person_id)

        if _status is False:
            # If non-members is allowed:
            if self.allow_non_members() is True:
                _, self.first_name, self.last_name, self.email = self._get_nif_api_person(self.person_id)

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
            "activities": self.activities,
            "aud": self.client_id,
            "sub": self.email,
        }

        if CLIENTS[self.client_id].get('roles', False) is True:
            roles = []
            for org in CLIENTS[self.client_id].get('orgs', []):
                roles.extend(lungo.get_person_roles_in_org(self.person_id, org))
            roles.extend(lungo.get_person_roles_from_competences(self.person_id))
            payload['roles'] = roles

        id_token = jwt.encode(payload,
                              get_certificate_key(client_id=self.client_id, cert='private'),
                              algorithm='RS256')

        return id_token

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
            claims = jwt.decode(token, verify=False, algorithms=['RS256'])

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
