import json
# import ssl
import urllib.parse as urlparse

# from auth import (authenticate_user_credentials, generate_access_token,
#                  verify_client_info, JWT_LIFE_SPAN)
from auth import Auth, JWT_LIFE_SPAN, JWT_INTITAL, _is_nif_maintanance
from flask import Flask, redirect, render_template, request, session, abort
from urllib.parse import urlencode
from csfr import generate_csrf_token
from settings import ERR, API_URL, API_HEADERS
import requests
import logging
import base64

app = Flask(__name__)
app.config.update(dict(
    SECRET_KEY="frewihuiowrhwerihrewiruihewirhiulw",
    WTF_CSRF_SECRET_KEY="ewkrpewkjrpiewji0othuwhuohfouh"
))
app.jinja_env.globals['csrf_token'] = generate_csrf_token

app.logger.setLevel(logging.DEBUG)


def get_lungo_person(person_id):
    try:
        r = requests.get('{}/persons/{}?projection={{"full_name": 1, "address": 1}}'.format(API_URL, person_id),
                         headers=API_HEADERS)

        if r.status_code == 200:

            resp = r.json()

            try:
                email = resp.get('address', {}).get('email')[0]
            except:
                email = ''

            return resp.get('full_name', 'Ukjent Navn'), email

    except Exception as e:
        # print("ERROR", e)
        pass

    return 'Ukjent Navn', ''


# Cookie consent jinja processor
@app.context_processor
def inject_template_scope():
    injections = dict()

    def cookies_check():
        value = request.cookies.get('cookie_consent')
        return value == 'true'

    injections.update(cookies_check=cookies_check)

    return injections


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


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return render_template('error.html',
                           client_name='Unknown',
                           client_id='Unknown',
                           redirect_uri='Unknown',
                           page_error='Invalid Request',
                           error_msg=ERR['invalid_request']['descr'])


@app.before_request
def csrf_protect():
    if request.method == "POST" and request.endpoint == 'signin':

        # print('FORM', request.form.get('_csrf_token'))
        token = session.pop('_csrf_token', None)
        # print('Session', token)
        if not token or token != request.form.get('_csrf_token'):
            #  print('CSFR')
            abort(403)


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route('/auth')
def auth():
    if _is_nif_maintanance() is True:
        return process_error('nif_down')
    # Describe the access request of the client and ask user for approval
    client_id = request.args.get('client_id', None)
    redirect_uri = request.args.get('redirect_uri', None)
    response_type = request.args.get('response_type', None)
    scope = request.args.get('scope', None)
    shebang = request.args.get('shebang', 0)

    if None in [client_id, redirect_uri, response_type]:
        return process_error('invalid_request', redirect_uri=redirect_uri, shebang=shebang)

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

    return render_template('login_page.html',
                           client_name=_auth.client.get('name', 'Ukjent'),
                           client_scope=_auth.client.get('scope', 'read'),
                           client_id=client_id,
                           redirect_uri=redirect_uri,
                           response_type=response_type,
                           shebang=shebang)


@app.route('/signin', methods=['GET', 'DELETE', 'PATCH', 'PUT', 'HEAD'])
def wrong_hole():
    return process_error('unsupported_response_type')


@app.route('/signin', methods=['POST'])
def signin():
    # Issues authorization code
    username = request.form.get('username', None)
    password = request.form.get('password', None)

    client_id = request.form.get('client_id', None)
    redirect_uri = request.form.get('redirect_uri', None)
    response_type = request.form.get('response_type', None)
    scope = request.form.get('scope', None)
    shebang = request.form.get('shebang', 0)

    if None in [username, password, client_id, redirect_uri, response_type, scope]:
        return process_error('invalid_request', redirect_uri, shebang)

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

    if not _auth.authenticate_user_credentials(username, password, client_id):
        return process_error('access_denied', redirect_uri, shebang)

    access_token = _auth.generate_access_token(expiry=JWT_INTITAL)

    # print('Test ')
    # print(_auth.refresh_token(access_token))

    return redirect(process_redirect_uri(redirect_uri,
                                         {
                                             _auth.client.get('response_type', 'access_token'): access_token,
                                             'token_type': 'JWT',
                                             'expires_in': JWT_INTITAL,
                                             'scope': _auth.client.get('scope', 'read'),
                                         },
                                         shebang), code=302)


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


@app.route('/confluence/token', methods=['POST'])
def confluence_token():
    token = request.form.get('code', None)
    client_id = request.form.get('client_id', None)
    redirect_uri = request.form.get('redirect_uri', None)
    grant_type = request.form.get('grant_type', None)
    client_secret = request.form.get('client_secret', None)

    # print('Form: ', request.form)
    # print('Vals: ', request.args)
    # print('JSON: ', request.json)

    if grant_type == 'authorization_code':

        _auth = Auth(client_id)
        # print(_auth.decoded_token)

        if token is not None and _auth.verify_client_secret(client_secret):
            if _auth.verify_token(token) is True:
                _auth.person_id = _auth.decoded_token.get('person_id')
                _auth.client_id = _auth.decoded_token.get('client_id')
                _auth.melwin_id = _auth.decoded_token.get('melwin_id', 0)

                access_token = _auth.generate_access_token(expiry=JWT_INTITAL)
                refresh_token = _auth.generate_access_token(expiry=JWT_INTITAL)
                # print('Test ')
                # print(_auth.refresh_token(access_token))

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
                    name, email = get_lungo_person(person_id)
                    # @TODO get real name from Lungo
                    return json.dumps({
                        'person_id': person_id,
                        'email': email,
                        'name': name
                    }), 200
    except:
        pass

    return json.dumps({
        'error': 'access_denied'
    }), 401


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

    page_error = None
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
    app.run(port=8080, debug=True)
