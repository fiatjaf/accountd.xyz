from flask import redirect, url_for

try:
    from .main import app
except SystemError:
    from main import app


def handle():
    callback = app.config['SERVICE_URL'] + url_for('.callback', provider='test')
    return redirect(callback)


def callback():
    return 'anything@test' if app.config['DEBUG'] or app.testing else None
