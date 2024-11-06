import unittest
import json
from flask_sqlalchemy import SQLAlchemy
from app import app
from models import setup_db
import os

ASSISTANT_TOKEN = os.getenv('ASSISTANT_TOKEN')
DIRECTOR_TOKEN = os.getenv('DIRECTOR_TOKEN')
PRODUCER_TOKEN = os.getenv('PRODUCER_TOKEN')


class CastingAgencyTestCase(unittest.TestCase):
    def setUp(self):
        self.director_header = {'Authorization': 'Bearer ' + DIRECTOR_TOKEN}
        self.assistant_header = {'Authorization': 'Bearer ' + ASSISTANT_TOKEN}
        self.producer_header = {'Authorization': 'Bearer ' + PRODUCER_TOKEN}
        self.app = app
        self.client = self.app.test_client
        setup_db(self.app)

        with self.app.app_context():
            self.db = SQLAlchemy()
            self.db.init_app(self.app)
            self.db.create_all()

#actors
    def test_get_actors_success(self):
        res = self.client().get('/actors', headers=self.assistant_header)
        data = json.loads(res.data)
        self.assertTrue(data['success'])


    def test_get_actors_fail(self):
        res = self.client().get('/actors', headers='')
        data = json.loads(res.data)
        self.assertFalse(data['success'])


    def test_post_actors_success(self):
        actor = {
            'name': 'actor1',
            'age': 20,
            'gender': 'man'
        }
        res_post = self.client().post('/actors', json=actor, headers=self.director_header)
        data_post = json.loads(res_post.data)
        self.assertTrue(data_post['success'])

    def test_post_actors_fail(self):
        actor = {
            'name': 'actor1',
            'age': 20,
            'gender': 'man'
        }
        res_post = self.client().post('/actors', json=actor, headers=self.assistant_header)
        data_post = json.loads(res_post.data)
        self.assertFalse(data_post['success'])


    def test_edit_actors_success(self):
        actor = {
            'name': 'actor1',
            'age': 20,
            'gender': 'man'
        }
        res_post = self.client().post('/actors', json=actor, headers=self.producer_header)
        data_post = json.loads(res_post.data)
        self.assertTrue(data_post['success'])
        res = self.client().patch(
            '/actors/' + str(data_post['actor']['id']), json=data_post['actor'], headers=self.producer_header)
        data = json.loads(res.data)
        self.assertTrue(data['success'])

    def test_edit_actors_fail(self):
        actor = {
            'name': 'actor1',
            'age': 20,
            'gender': 'man'
        }
        res_post = self.client().post('/actors', json=actor, headers=self.assistant_header)
        data_post = json.loads(res_post.data)
        self.assertTrue(data_post['success'])
        res = self.client().patch(
            '/actors/' + str(data_post['actor']['id']), json=data_post['actor'], headers=self.assistant_header)
        data = json.loads(res.data)
        self.assertFalse(data['success'])


    def test_delete_actors_success(self):
        actor = {
            'name': 'actor1',
            'age': 20,
            'gender': 'man'
        }
        res_post = self.client().post('/actors', json=actor, headers=self.director_header)
        data_post = json.loads(res_post.data)
        self.assertTrue(data_post['success'])
        res = self.client().delete(
            '/actors/' + str(data_post['actor']['id']), headers=self.director_header)
        data = json.loads(res.data)
        self.assertTrue(data['success'])


    def test_delete_actors_fail(self):
        actor = {
            'name': 'actor1',
            'age': 20,
            'gender': 'man'
        }
        res_post = self.client().post('/actors', json=actor, headers=self.assistant_header)
        data_post = json.loads(res_post.data)
        self.assertTrue(data_post['success'])
        res = self.client().delete(
            '/actors/' + str(data_post['actor']['id']), headers=self.assistant_header)
        data = json.loads(res.data)
        self.assertFalse(data['success'])


    def test_get_movies_success(self):
        res = self.client().get('/movies', headers=self.assistant_header)
        data = json.loads(res.data)
        self.assertTrue(data['success'])


    def test_get_movies_fail(self):
        res = self.client().get('/movies', headers='')
        data = json.loads(res.data)
        self.assertFalse(data['success'])


    def test_post_movie_success(self):
        movie = {
            "title": "movie1",
            "release_date": "05/11/2024"
        }
        res_post = self.client().post('/movies', json=movie, headers=self.producer_header)
        data_post = json.loads(res_post.data)
        self.assertTrue(data_post['success'])

    def test_post_movie_fail(self):
        movie = {
            "title": "movie1",
            "release_date": "05/11/2024"
        }
        res_post = self.client().post('/movies', json=movie, headers=self.director_header)
        data_post = json.loads(res_post.data)
        self.assertFalse(data_post['success'])


    def test_edit_movie_success(self):
        movie = {
            "title": "movie1",
            "release_date": "05/11/2024"
        }
        res_post = self.client().post('/movies', json=movie, headers=self.director_header)
        data_post = json.loads(res_post.data)
        self.assertTrue(data_post['success'])
        res = self.client().patch(
            '/movies/' + str(data_post['movie']['id']), json=data_post['movie'], headers=self.director_header)
        data = json.loads(res.data)
        self.assertTrue(data['success'])


    def test_edit_movie_fail(self):
        movie = {
            "title": "movie1",
            "release_date": "05/11/2024"
        }
        res_post = self.client().post('/movies', json=movie, headers=self.assistant_header)
        data_post = json.loads(res_post.data)
        self.assertTrue(data_post['success'])
        if data_post['success'] != False:
            res = self.client().patch(
                '/movies/' + str(data_post['movie']['id']), json=data_post['movie'], headers=self.assistant_header)
            data = json.loads(res.data)
            self.assertFalse(data['success'])


    def test_delete_movie_success(self):
        movie = {
            "title": "movie1",
            "release_date": "05/11/2024"
        }
        res_post = self.client().post('/movies', json=movie, headers=self.producer_header)
        data_post = json.loads(res_post.data)
        self.assertTrue(data_post['success'])
        res = self.client().delete(
            '/movies/' + str(data_post['movie']['id']), headers=self.producer_header)
        data = json.loads(res.data)
        self.assertTrue(data['success'])


    def test_delete_movie_fail(self):
        movie = {
            "title": "movie1",
            "release_date": "05/11/2024"
        }
        res_post = self.client().post('/movies', json=movie, headers=self.assistant_header)
        data_post = json.loads(res_post.data)
        self.assertFalse(data_post['success'])
        if data_post['success'] != False:
            res = self.client().delete(
                '/movies/' + str(data_post['movie']['id']), headers=self.assistant_header)
            data = json.loads(res.data)
            self.assertFalse(data['success'])


if __name__ == "__main__":
    unittest.main()
