import os
import jwt
import json

from baseclass import TestCase
from app import pg


class TestAuthFlow(TestCase):
    def test_landing(self):
        r = self.app.get('/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, b'hello')

    def test_get_public_key(self):
        r = self.app.get('/public-key')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, os.getenv('PUBLIC_KEY').replace('\\n', '\n').encode('ascii'))

    def test_auth_flow(self):
        r = self.app.get('/login/banana/with/banana@test')
        self.assertEqual(r.status_code, 302)
        self.assertIn('callback/{}/with/{}'.format('banana', 'banana%40test'), r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 302)
        self.assertIn('authorized/{}/with/{}'.format('banana', 'banana%40test'), r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 200)
        token = r.data

        # verify locally
        payload = jwt.decode(
            token,
            os.getenv('PUBLIC_KEY').replace('\\n', '\n').encode('ascii'),
            algorithms='RS256'
        )
        self.assertEqual(payload['user'], 'banana')

        # use the /verify endpoint
        r = self.app.post('/verify/' + token.decode('utf-8'))
        self.assertEqual(json.loads(r.data.decode('utf-8'))['user'], 'banana')

        # test the lookup endpoint
        r = self.app.get('/lookup/' + payload['user'])
        user = json.loads(r.data.decode('utf-8'))
        self.assertEqual(user['id'], 'banana')
        self.assertEqual(len(user['accounts']), 1)
        self.assertEqual(user['accounts'][0]['type'], 'test')
        self.assertEqual(user['accounts'][0]['account'], 'banana@test')

    def test_lookup(self):
        with pg.cursor() as c:
            c.execute('''insert into accounts values ('xamuza.com', 'xamuza')''')
            c.execute('''insert into accounts values ('x@muza.com', 'xamuza')''')
        pg.commit()

        r = self.app.get('/lookup/xamuza')
        user = json.loads(r.data.decode('utf-8'))
        self.assertEqual(user['id'], 'xamuza')
        self.assertEqual(len(user['accounts']), 2)
        self.assertEqual(user['accounts'][0]['type'], 'domain')
        self.assertEqual(user['accounts'][0]['account'], 'xamuza.com')
        self.assertEqual(user['accounts'][1]['type'], 'email')
        self.assertEqual(user['accounts'][1]['account'], 'x@muza.com')
