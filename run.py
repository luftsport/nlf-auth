import json
import urllib.parse as urlparse
from auth import Auth, JWT_LIFE_SPAN, JWT_INTITAL, generate_state, decode_state
from flask import Flask, redirect, render_template, request
from urllib.parse import urlencode
from settings import (
    ERR,
    CLIENT_BASE_URL,
    CLIENT_ID,
    SERVER_BASE_URL,
    SERVER_PROXY_SIGNING,
    SERVER_PROXY_AUTH,
    SERVER_PORT,
    SERVER_DEBUG,
    OIDC_PROTOCOL,
    OIDC_AUTH_URL,
    OIDC_TOKEN_URL,
    OIDC_USER_INFO_URL,
    OIDC_LOGOUT_URL,
    OIDC_CONFIG_URL

)

from lungo import get_lungo_person
import logging
from oidc import OIDC
import time

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)


def process_redirect_uri(redirect_uri, new_entries, shebang=False):
    # Prepare the redirect URL
    url_parts = list(urlparse.urlparse(redirect_uri))

    if int(shebang) == 1:
        if url_parts[2].endswith('/'):
            url_parts[2] = '%s#!/' % url_parts[2]
        else:
            url_parts[2] = '%s/#!/' % url_parts[2]

    queries = dict(urlparse.parse_qsl(url_parts[4]))
    queries.update(new_entries)
    url_parts[4] = urlencode(queries)
    url = urlparse.urlunparse(url_parts)

    return url


def process_error(error, redirect_uri=None, shebang=0):
    """A simple redirect uri with oauth2 errors"""
    if ERR[error]['code'] >= 500 or redirect_uri is None:
        return render_template('error.html',
                               error_msg=ERR[error]['descr'],
                               error_code=ERR[error]['code']), ERR[error]['code']

    return redirect(process_redirect_uri(redirect_uri,
                                         {
                                             'error': error,
                                             'error_description': ERR[error]['descr']
                                         },
                                         shebang),
                    code=ERR[error]['code'])


@app.route('/{}'.format(SERVER_PROXY_AUTH), methods=['GET'])
def oidc_proxy_chain():
    """
    The main entry point for OIDC

    Just check, build a state parameter then redirect; proxy chain
    :return:
    """

    # Parse input
    client_id = request.args.get('client_id', None)
    redirect_uri = request.args.get('redirect_uri', None)
    response_type = request.args.get('response_type', None)
    scope = request.args.get('scope', None)
    shebang = request.args.get('shebang', 0)

    if None in [client_id, redirect_uri, response_type]:
        return process_error('invalid_request', redirect_uri=redirect_uri, shebang=shebang)

    # Instantiate auth
    _auth = Auth(client_id)

    if len(_auth._get_client()) == 0:
        return process_error('invalid_request')

    # First verify redirect_uri
    if not _auth.verify_redirect_uri(redirect_uri):
        return process_error('invalid_request')

    if scope is None or _auth.verify_scope(scope) is False:
        return process_error('invalid_scope', redirect_uri=redirect_uri, shebang=shebang)

    if not _auth.verify_response_type(response_type):
        return process_error('invalid_request', redirect_uri=redirect_uri, shebang=shebang)

    _state = generate_state(request.args)

    # NIF OIDC params
    params = {'client_id': CLIENT_ID,
              'redirect_uri': '{}/{}'.format(SERVER_BASE_URL, SERVER_PROXY_SIGNING),
              'state': _state,
              'response_type': 'code',
              'scope': 'openid roles web-origins'}

    return redirect(process_redirect_uri(OIDC_AUTH_URL, params), code=302)


@app.route('/{}'.format(SERVER_PROXY_SIGNING), methods=['GET'])
def oidc_ret():
    try:
        token = None

        state = request.args.get('state')
        args = decode_state(state=state)

        _auth = Auth(client_id=args.get('client_id', None))

        oidc = OIDC()

        authz_status, authorization = oidc.get_authorization(code=request.args.get('code', None))

        if authz_status is True:
            user_status, user = oidc.get_user_info(token=authorization.get('access_token', None))

            if user_status is True:

                person_status, person_id = oidc.get_person_id(user.get('bp_id_sub', None))

                if person_status is True:

                    _auth.person_id = person_id

                    # Verify activity!
                    if _auth.verify_activity() is not True:
                        return process_error('access_denied',
                                             redirect_uri=args.get('redirect_uri', None),
                                             shebang=args.get('shebang', False))

                    _auth.get_melwin_id(person_id)

                    token = _auth.generate_access_token()

                    # User successfully authenticated!
                    return redirect(process_redirect_uri(args.get('redirect_uri', None),
                                                         {
                                                             _auth.client.get('response_type', 'access_token'): token,
                                                             'token_type': 'JWT',
                                                             'expires_in': JWT_INTITAL,
                                                             'scope': _auth.client.get('scope', 'read'),
                                                         },
                                                         args.get('shebang', False)), code=302)
        else:
            return process_error('access_denied',
                                 redirect_uri=args.get('redirect_uri', None),
                                 shebang=args.get('shebang', False))
    except Exception as e:
        app.logger.exception('Could not authenticate')

    return process_error('server_error',
                         redirect_uri=args.get('redirect_uri', None),
                         shebang=args.get('shebang', False))


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return render_template('error.html',
                           client_name='Unknown',
                           client_id='Unknown',
                           redirect_uri='Unknown',
                           page_error='Invalid Request',
                           error_msg=ERR['invalid_request']['descr'])


@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, public, max-age=0'
    response.headers['Expires'] = 0
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/signin', methods=['GET', 'DELETE', 'PATCH', 'PUT', 'HEAD'])
def wrong_method():
    return process_error('unsupported_response_type')


@app.route('/revoke', methods=['POST'])
def revoke():
    token = request.get_json(force=True).get('access_token', None)
    client_id = request.get_json(force=True).get('client_id', None)

    _auth = Auth(client_id)

    new_token = _auth.refresh(token)

    if new_token is False:
        return json.dumps({
            "error": "invalid_token"
        }), 401
    else:
        return json.dumps({
            'access_token': new_token,
            'token_type': 'JWT',
            'expires_in': JWT_LIFE_SPAN
        }), 200


@app.route('/verify', methods=['POST'])
def verify():
    token = request.get_json(force=True).get('access_token', None)
    client_id = request.get_json(force=True).get('client_id', None)

    _auth = Auth(client_id)

    if token is not None:
        if _auth.verify_token(token) is True:
            return json.dumps({
                'access_token': token
            }), 200

    return json.dumps({
        'error': 'access_denied'
    }), 401


@app.route('/introspection', methods=['POST'])
def introspection():
    """
    The protected resource calls the introspection endpoint using an HTTP
    POST [RFC7231] request with parameters sent as
    "application/x-www-form-urlencoded
    :return:
    """
    token = request.form.get('access_token', None)
    client_id = request.form.get('client_id', None)
    client_secret = request.form.get('client_secret', None)

    if client_id is not None:

        _auth = Auth(client_id)

        if token is not None and _auth.verify_client_secret(client_secret):
            if _auth.verify_token(token) is True:
                _auth.person_id = _auth.decoded_token.get('person_id')
                _auth.client_id = _auth.decoded_token.get('client_id')
                _auth.melwin_id = _auth.decoded_token.get('melwin_id', 0)

                access_token = _auth.generate_access_token(expiry=JWT_INTITAL)
                refresh_token = _auth.generate_access_token(expiry=JWT_INTITAL)

                return json.dumps({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "expires_in": _auth.decoded_token.get('exp', time.time()) - time.time(),
                    "issuer": _auth.decoded_token.get('iss'),
                    "scope": "read",
                    "person_id": _auth.decoded_token.get('person_id'),
                    "melwin_id": _auth.decoded_token.get('melwin_id', 0)
                }), 200

        return json.dumps({
            'error': 'access_denied'
        }), 401

    return json.dumps({
        'error': 'unsupported_response_type'
    }), 401


@app.route('/confluence/token', methods=['POST'])
def confluence_token():
    token = request.form.get('code', None)
    client_id = request.form.get('client_id', None)
    redirect_uri = request.form.get('redirect_uri', None)
    grant_type = request.form.get('grant_type', None)
    client_secret = request.form.get('client_secret', None)

    if grant_type == 'authorization_code':

        _auth = Auth(client_id)

        if token is not None and _auth.verify_client_secret(client_secret):
            if _auth.verify_token(token) is True:
                _auth.person_id = _auth.decoded_token.get('person_id')
                _auth.client_id = _auth.decoded_token.get('client_id')
                _auth.melwin_id = _auth.decoded_token.get('melwin_id', 0)

                access_token = _auth.generate_access_token(expiry=JWT_INTITAL)
                refresh_token = _auth.generate_access_token(expiry=JWT_INTITAL)

                return json.dumps({
                    "access_token": access_token,
                    "token_type": "bearer",
                    "expires_in": _auth.decoded_token.get('iss'),
                    "refresh_token": refresh_token,
                    "scope": "read",
                    "person_id": _auth.decoded_token.get('person_id')
                }), 200

        return json.dumps({
            'error': 'access_denied'
        }), 401

    return json.dumps({
        'error': 'unsupported_response_type'
    }), 401


@app.route('/confluence/user', methods=['GET'])
def confluence_user():
    try:
        authorzation = request.headers.get('Authorization')
        token = authorzation.strip().split('Bearer ')[1]

        _auth = Auth(None)
        client_id = _auth.get_client_id_from_token(token)

        if None not in [token, client_id]:

            _auth = Auth(client_id)

            if _auth.verify_token(token) is True:

                person_id = _auth.decoded_token.get('person_id', 0)

                if person_id is not False and person_id > 0:
                    _status, first_name, last_name, email = get_lungo_person(person_id)
                    # @TODO get real name from Lungo
                    return json.dumps({
                        'person_id': person_id,
                        'email': email,
                        'name': first_name.strip() + ' ' + last_name.strip()
                    }), 200

    except Exception as e:
        app.logger.exception('Could not get Confluence User')

    return json.dumps({
        'error': 'access_denied'
    }), 401


@app.route('/logout', methods=['GET'])
def logout():
    client_id = request.args.get('client_id', None)
    redirect_uri = request.args.get('redirect_uri', '')
    _state = generate_state({'client_id': client_id, 'redirect_uri': redirect_uri})
    if client_id is not None:
        _auth = Auth(client_id)
        params = {'redirect_uri': '{}/logged/out/{}'.format(SERVER_BASE_URL, _state)}
        return redirect(process_redirect_uri(OIDC_LOGOUT_URL, params), code=302)

    return process_error('server_error',
                         redirect_uri=redirect_uri,
                         shebang=request.args.get('shebang', False))


@app.route('/logged/out/<string:_state>', methods=['GET'])
def logged_out(_state):
    args = decode_state(state=_state)
    client_id = args.get('client_id', None)
    return_uri = args.get('redirect_uri', '')

    if client_id is not None:
        _auth = Auth(client_id)
        if _auth.verify_redirect_uri(return_uri) is True:
            return redirect(return_uri, code=302)

    return process_error('server_error',
                         redirect_uri=return_uri,
                         shebang=args.get('shebang', False))



@app.route('/user', methods=['POST'])
def user():
    token = request.get_json(force=True).get('access_token', None)
    _auth = Auth(None)
    client_id = _auth.get_client_id_from_token(token)

    if None not in [token, client_id]:
        _auth = Auth(client_id)
        person_id = _auth.get_user_id(token)

        if person_id is not False and person_id > 0:
            return json.dumps({
                'person_id': person_id,

            }), 200

    return json.dumps({
        'error': 'access_denied'
    }), 401


@app.route('/error', methods=['GET'])
def error():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    error = request.args.get('error')
    page_error = None

    _auth = Auth(client_id)

    if None in [client_id, redirect_uri]:
        page_error = "invalid_request"

    if not _auth.verify_redirect_uri(redirect_uri):
        page_error = "invalid_client"

    return render_template('error.html',
                           client_name=_auth.client.get('name', 'Ukjent'),
                           client_id=client_id,
                           redirect_uri=redirect_uri,
                           page_error=page_error,
                           error_msg=error)


@app.route('/help', methods=['GET'])
def help():
    # Issues authorization code
    client_id = request.args.get('client_id', None)
    redirect_uri = request.args.get('redirect_uri', None)
    response_type = request.args.get('response_type', None)
    scope = request.args.get('scope', None)
    shebang = request.args.get('shebang', 0)

    _auth = Auth(client_id)

    if len(_auth._get_client()) == 0:
        return process_error('invalid_request')

    # First verify redirect_uri
    if not _auth.verify_redirect_uri(redirect_uri):
        return process_error('invalid_request')

    if scope is None or _auth.verify_scope(scope) is False:
        return process_error('invalid_scope', redirect_uri=redirect_uri, shebang=shebang)

    if not _auth.verify_response_type(response_type):
        return process_error('invalid_request', redirect_uri=redirect_uri, shebang=shebang)

    return render_template('help.html',
                           client_name=_auth.client.get('name', 'Unknown'),
                           client_scope=scope,
                           client_id=client_id,
                           redirect_uri=redirect_uri,
                           response_type=response_type,
                           shebang=shebang)


if __name__ == '__main__':
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # context.load_cert_chain('domain.crt', 'domain.key')
    # app.run(port = 5000, debug = True, ssl_context = context)
    app.run(port=SERVER_PORT, debug=SERVER_DEBUG)
