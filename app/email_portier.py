import random

from portier.client import get_verified_email
from flask import session, request, url_for

try:
    from .main import app
except SystemError:
    from main import app

PORTIER_BROKER = 'https://broker.portier.io'


def handle(user, account):
    nonce = '{}'.format(random.random())
    redirect = app.config['SERVICE_URL'] + url_for(
        '.callback',
        user=user, account=account,
    )

    cache = Cache()
    cache.set('portier:nonce:%s' % nonce, redirect, 0)

    return '''
<form id="form" action="{portier}/auth" method="post" style="display:none;">
  <input name="login_hint" value="{email}">
  <input name="scope" value="openid email">
  <input name="response_type" value="id_token">
  <input name="response_mode" value="form_post">
  <input name="redirect_uri" value="{redirect}">
  <input name="client_id" value="{url}">
  <input name="nonce" value="{nonce}">
</form>
<script>document.getElementById('form').submit()</script>
    '''.format(portier=PORTIER_BROKER,
               email=account,
               redirect=redirect,
               url=app.config['SERVICE_URL'],
               nonce=nonce)


def callback(user, account):
    try:
        email, _ = get_verified_email(
            broker_url=PORTIER_BROKER,
            token=request.form['id_token'],
            audience=app.config['SERVICE_URL'],
            issuer=PORTIER_BROKER,
            cache=Cache()
        )
    except RuntimeError as exc:
        raise exc

    return email == account


class Cache(object):
    def get(self, key):
        return session.get('pc:' + key)

    def set(self, key, value, timeout):
        session['pc:' + key] = value

    def delete(self, key):
        session.pop('pc:' + key)
