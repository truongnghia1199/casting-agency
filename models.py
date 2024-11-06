import os
from sqlalchemy import Column, String, Integer, Date
from flask_sqlalchemy import SQLAlchemy
import json
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
database_path = os.getenv('DATABASE_PATH')


def setup_db(app):
    app.config["SQLALCHEMY_DATABASE_URI"] = database_path
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.app = app
    db.init_app(app)


def db_drop_and_create_all():
    db.drop_all()
    db.create_all()

    actor = Actors(
        name='actor1',
        age=20,
        gender='men'
    )

    actor.insert()

    movie = Movies(
        title='movie1',
        release_date='05/11/2024'
    )

    movie.insert()


class Actors(db.Model):
    __tablename__ = 'actors'
    id = Column(Integer().with_variant(
        Integer, "postgresql"), primary_key=True)
    name = Column(String(100))
    age = Column(Integer)
    gender = Column(String(100))

    def format(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'gender': self.gender,
        }

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def __repr__(self):
        return json.dumps(self.format())


class Movies(db.Model):
    __tablename__ = 'movies'
    id = Column(Integer().with_variant(
        Integer, "postgresql"), primary_key=True)
    title = Column(String(100))
    release_date = Column(Date)

    def format(self):
        return {
            'id': self.id,
            'title': self.title,
            'release_date': self.release_date,
        }

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def __repr__(self):
        return json.dumps(self.format())
