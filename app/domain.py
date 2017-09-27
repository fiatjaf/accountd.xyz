import os
from urllib import parse

import requests
from flask import redirect, url_for, request

TYPE = 'domain'


def handle(user, account):
    return redirect('https://indieauth.com/auth?' + parse.urlencode({
        'me': account,
        'client_id': os.getenv('SERVICE_URL'),
        'redirect_uri': _redirect_uri(user, account)
    }))


def callback(user, account):
    code = request.args['code']
    r = requests.post('https://indieauth.com/auth', data={
        'code': code,
        'redirect_uri': _redirect_uri(user, account),
        'client_id': os.getenv('SERVICE_URL')
    }, headers={'Accept': 'application/json'})
    if not r.ok:
        raise Exception(r.text)

    return account == parse.urlparse(r.json()['me']).hostname


def _redirect_uri(user, account):
    return os.getenv('SERVICE_URL') + url_for(
        '.callback',
        type=TYPE, user=user, account=account,
    )
