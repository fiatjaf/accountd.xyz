import os
import unittest

from app import app, pg


if 'amazonaws' in os.getenv('DATABASE_URL'):
    os.exit(1)

class TestCase(unittest.TestCase):
    def setUp(self):
        app.testing = True
        self.app = app.test_client()

        pg.rollback()
        with pg.cursor() as c:
            c.execute('drop table if exists accounts')
            with open('postgres.sql') as f:
                c.execute(f.read())
        pg.commit()

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
