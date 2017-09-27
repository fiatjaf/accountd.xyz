import re
import random
from urllib import parse

from flask import session, request, redirect, render_template

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
    session['other_account'] = None

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
    if session['user'] != user:
        return 'wrong user, go to /login first', 403

    if session.get('other_account') == account:
        # if this exists, it means `other_account` is being used
        # to authorize the new `account` into `user`.
        valid = globals()[type].callback(user, account)
        if valid:
            return render_template('authorize-new.html', type=type)
        else:
            return '0'

    if session['account'] != account:
        return 'wrong account, go to /login first', 403

    valid = globals()[type].callback(user, account)

    # make link on our database
    if valid:
        with pg:
            with pg.cursor() as c:
                c.execute(
                    'INSERT INTO users (id) VALUES (%s) '
                    'ON CONFLICT DO NOTHING '
                    'RETURNING id',
                    (user,)
                )

                if c.rowcount == 0:
                    # there was a conflict
                    c.execute(
                        'SELECT type, account FROM accounts '
                        'WHERE user_id = %s AND type != %s',
                        (user, type)
                    )

                    pg.rollback()

                    other_type, other_account = c.fetchone()
                    session['other_account'] = other_account
                    return globals()[other_type].handle(user, other_account)

                c.execute(
                    'INSERT INTO accounts (type, account, user_id) '
                    'VALUES (%s, %s, %s)',
                    (type, account, user)
                )

    return return_response(valid)


@app.route('/authorize/<type>/<account>/on/<user>/with/<other_account>',
           methods=['POST'])
def authorize(type, account, user, other_account):
    if session['account'] != account or \
            session['user'] != user or \
            session['other_account'] != other_account:
        return 'wrong user/account, go to /login first', 403

    with pg:
        with pg.cursor() as c:
            c.execute(
                'INSERT INTO accounts (type, account, user_id) '
                'VALUES (%s, %s, %s) '
                'ON CONFLICT (account) '
                'DO UPDATE SET user_id = %s',
                (type, account, user, user)
            )

    return return_response(True)


def return_response(valid):
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
