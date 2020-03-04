import string
import random
from flask import session


def id_generator(size=24, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = id_generator()
    return session['_csrf_token']
