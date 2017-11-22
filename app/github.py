import os
import json
import random
from urllib.parse import urlencode

from flask import redirect, url_for, request, session
import requests

try:
    from .app import app
except SystemError:
    from app import app

consumer_key = os.getenv('GITHUB_KEY')
consumer_secret = os.getenv('GITHUB_SECRET')


def handle(user, account):
    callback = app.config['SERVICE_URL'] + url_for(
        '.callback', user=user, account=account)

    nonce = random.random()
    session['gh:nonce'] = nonce

    return redirect(
        'https://github.com/login/oauth/authorize?' + urlencode({
            'redirect_uri': callback,
            'client_id': consumer_key,
            'state': nonce
        })
    )


def callback(user, account):
    callback = app.config['SERVICE_URL'] + url_for(
        '.callback', user=user, account=account)

    r = requests.post(
        'https://github.com/login/oauth/access_token',
        data=json.dumps({
            'code': request.args['code'],
            'client_id': consumer_key,
            'client_secret': consumer_secret,
            'redirect_uri': callback,
            'nonce': session['gh:nonce']
        }),
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
    )

    del session['gh:nonce']

    if not r.ok:
        raise Exception('failed to fetch access token from github.')

    token = r.json().get('access_token')
    r = requests.get(
        'https://api.github.com/user',
        headers={
            'User-Agent': 'accountd.xyz',
            'Authorization': 'token ' + token,
            'Content-Type': 'application/json',
            'Accept': 'application/vnd.github.v3+json',
        }
    )

    if not r.ok:
        raise Exception('failed to fetch user login from github after oauth.')

    return r.json()['login'] == account.split('@')[0]