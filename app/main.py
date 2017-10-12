import random
from urllib import parse

from flask import session, request, redirect, render_template, \
                  jsonify

try:
    from .app import app, redis, pg
    from .helpers import account_type
    from . import email_portier as email
    from . import domain
    from . import twitter
except SystemError:
    from app import app, redis, pg
    from helpers import account_type
    import email_portier as email
    import domain
    import twitter


# satisfy flake8
def x(*args): None
x(email, domain, twitter)
# ~


@app.route('/')
def index():
    return 'hello'


@app.route('/login/<user>/with/<account>')
@app.route('/login', defaults={'user': None, 'account': None})
def login(user, account):
    user = (user or request.args['user']).lower()
    account = (account or request.args['account']).lower()

    session['user'] = user
    session['account'] = account
    session['redirect_uri'] = request.args.get('redirect_uri')
    session['other_account'] = None

    type = account_type(account)

    try:
        return globals()[type].handle(user, account)
    except KeyError:
        return 'are you {}? what is {}?'.format(user, account), 404


@app.route('/callback/<user>/with/<account>', methods=['GET', 'POST'])
@app.route('/callback', defaults={'user': None, 'account': None})
def callback(user, account):
    user = user or request.args['user']
    account = account or request.args['account']

    if session['user'] != user:
        return 'wrong user, go to /login first', 403

    if session.get('other_account') == account:
        # if this exists, it means `other_account` is being used
        # to authorize the new `account` into `user`.
        type = account_type(account)
        valid = globals()[type].callback(user, account)
        if valid:
            return render_template('authorize-new.html', type=type)
        else:
            return '0'

    if session['account'] != account:
        return 'wrong account, go to /login first', 403

    type = account_type(account)
    valid = globals()[type].callback(user, account)

    # make link on our database
    if valid:
        with pg:
            with pg.cursor() as c:
                c.execute(
                    'SELECT account FROM accounts '
                    'WHERE user_id = %s',
                    (user,)
                )

                if c.rowcount == 0:
                    # user is new, register
                    c.execute(
                        'INSERT INTO accounts (user_id, account) '
                        'VALUES (%s, %s)',
                        (user, account)
                    )

                else:
                    # this user is already registered
                    alternatives = []

                    # the user must authorize the new account
                    # using one of the his previous accounts
                    for row in c.fetchall():
                        if row[0] == account:
                            # this same account has been registered
                            # so everything is fine
                            return return_response(valid, user)

                        alternatives.append(row[0])

                    if len(alternatives) == 1:
                        other_account = alternatives[0]
                        session['other_account'] = other_account
                        t = account_type(other_account)
                        return globals()[t].handle(user, other_account)
                    else:
                        return render_template('alternatives.html')

    return return_response(valid, user)


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
                'INSERT INTO accounts (account, user_id) '
                'VALUES (%s, %s) '
                'ON CONFLICT (account) '
                'DO UPDATE SET user_id = %s',
                (account, user, user)
            )

    return return_response(True, user)


@app.route('/verify/<code>', methods=['POST'])
def verify(code):
    user = redis.get('code:' + code)
    return user


@app.route('/is/<account>/<user>')
def is_(account, user):
    with pg:
        with pg.cursor() as c:
            c.execute(
                'SELECT user_id FROM accounts '
                'WHERE account = %s AND user_id = %s',
                (account, user)
            )
            if c.rowcount:
                return 'true'
            else:
                return 'false'


def return_response(valid, user):
    # pass response to external caller
    if session.get('redirect_uri'):
        code = int(random.random() * 999999999)

        u = parse.urlparse(session['redirect_uri'])
        qs = parse.parse_qs(u.query)
        qs['code'] = code
        back = u.scheme + '://' + u.netloc + u.path + '?' + parse.urlencode(qs)
        print(back)

        if valid:
            redis.setex('code:%s' % code, 180, user)

        return redirect(back)
    else:
        return 'true' if valid else 'false'


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=16725)
