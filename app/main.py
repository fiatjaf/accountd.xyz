import re
import random
from urllib import parse

from flask import session, request, redirect

try:
    from .app import app, redis, pg
    from . import email_portier as email
    from . import domain
except SystemError:
    from app import app, redis, pg
    import email_portier as email
    import domain


@app.route('/')
def index():
    return 'hello'


@app.route('/login/<user>/with/<account>')
def login(user, account):
    session['user'] = user
    session['account'] = account
    session['redirect_uri'] = request.args.get('redirect_url')

    if len(account.split('@')) == 1:
        if re.match(r'^\+\d+$', account):
            # if the account is a phone number
            # confirm it with an SMS
            return 'phone numbers not yet supported, check later', 403
        if len(account.split('.')) > 1:
            # if the account is a bare domain
            # confirm it with indieauth
            return domain.handle(user, account)

    # otherwise the account is in format <username>@<provider>
    name, provider = account.split('@')

    if len(provider.split('.')) > 1:
        # if the provider is something like domain.com
        # then it is a full domain and hence an email
        return email.handle(user, account)

    # otherwise it is a silo, to which we'll proceed using
    # one of our premade oauth authorizers
    if provider == 'github':
        pass
    elif provider == 'twitter':
        pass
    elif provider == 'reddit':
        pass
    elif provider == 'instagram':
        pass

    return 'are you {}? what is {}?'.format(name, provider), 404


@app.route('/callback/<type>/<user>/with/<account>', methods=['GET', 'POST'])
def callback(type, user, account):
    if session['user'] != user or session['account'] != account:
        return 'wrong user/account, go to /login first', 403

    valid = globals()[type].callback(user, account)

    # make link on our database
    if valid:
        with pg:
            with pg.cursor() as c:
                c.execute(
                    'INSERT INTO users (id) VALUES (%s) '
                    'ON CONFLICT DO NOTHING',
                    (user,)
                )
                c.execute(
                    'INSERT INTO accounts (type, account, user_id) '
                    'VALUES (%s, %s, %s)',
                    (type, account, user)
                )

    # pass response to external caller
    if session.get('redirect_uri'):
        code = int(random.random() * 999999999)

        u = parse.urlparse(session['redirect_uri'])
        qs = parse.parse_qs(u.query)
        qs['code'] = code
        u.query = parse.urlencode(qs)
        back = parse.urlunparse(u)

        redis.setex('code:' + code, 180, 1 if valid else 0)

        return redirect(back)
    else:
        return 'true' if valid else 'false'


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=16725)
