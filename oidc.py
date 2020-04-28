import requests
import base64

from settings import (
    CLIENT_ID,
    CLIENT_SECRET,
    CLIENT_BASE_URL,
    NIF_FEDERATION_USERNAME,
    NIF_FEDERATION_PASSWORD,
    NIF_REALM,
    SERVER_BASE_URL,
    SERVER_PROXY_SIGNING,
    # SERVER_PROXY_AUTH,
    # OIDC_PROTOCOL,
    OIDC_TOKEN_URL,
    OIDC_USER_INFO_URL,
    OIDC_CONFIG_URL
)

from nif_api import NifApiUser


# from flask import current_app as app


class OIDC:

    def __init__(self):
        pass

    def _get_basic_auth(self,
                        client_id=CLIENT_ID,
                        client_secret=CLIENT_SECRET):

        try:
            return True, base64.b64encode(bytes('{}:{}'.format(client_id, client_secret), 'utf-8')).decode('utf-8')
        except:
            pass

        return False, None

    def get_info(self):

        resp = requests.get(CLIENT_BASE_URL)

        if resp.status_code == 200:
            return True, resp.json()

        return False, {}

    def get_issuer(self):
        return self.get_info()

    def get_authorization(self, code, redirect_uri='{}/{}'.format(SERVER_BASE_URL, SERVER_PROXY_SIGNING)):

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri
        }

        status, auth = self._get_basic_auth()

        if status is True:
            headers = {'Authorization': 'Basic {}'.format(auth)}

            resp = requests.post(OIDC_TOKEN_URL,
                                 data=data,
                                 headers=headers
                                 )
            if resp.status_code == 200:
                return True, resp.json()

        return False, {}

    def get_user_info(self, token):

        headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/x-www-form-urlencoded'}

        resp = requests.get(OIDC_USER_INFO_URL, headers=headers)

        if resp.status_code == 200:
            return True, resp.json()

        return False, {}

    def get_person_id(self, buypass_id):

        api = NifApiUser(NIF_FEDERATION_USERNAME, NIF_FEDERATION_PASSWORD, log_file='nif_{}.log'.format(NIF_REALM), realm=NIF_REALM)

        status, person_id = api.get_person_id(buypass_id)

        return status, person_id

    def get_config(self):
        resp = requests.get(OIDC_CONFIG_URL)

        if resp.status_code == 200:
            return True, resp.json()

        return False, {}
