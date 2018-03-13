from flask import redirect, url_for

try:
    from .main import app
except SystemError:
    from main import app


def handle(user, account):
    callback = app.config['SERVICE_URL'] + url_for(
        '.callback', user=user, account=account)
    return redirect(callback)


def callback(user, account):
    return app.config['DEBUG'] or app.testing
