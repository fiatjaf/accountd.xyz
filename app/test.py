from flask import redirect, url_for, g, session

try:
    from .main import app
except SystemError:
    from main import app


def handle():
    callback = app.config['SERVICE_URL'] + url_for('.callback', provider='test')

    if hasattr(g, 'account'):
        session['test:account'] = g.account

    return redirect(callback)


def callback():
    account = (session.pop('test:account', 'anything@test'))
    return account if app.config['DEBUG'] or app.testing else None
