import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS
from models import setup_db, db_drop_and_create_all, Actors, Movies
from auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

db_drop_and_create_all()


@app.route('/')
def hello():
    return "hello world!"


#ACTOR
@app.route('/actors')
@requires_auth("get:actors", methods=["GET"])
def get_actors(payload):
    actors = Actors.query.all()
    return jsonify({"success": True, "actors": [actor.format() for actor in actors]})


@app.route('/actors', methods=["POST"])
@requires_auth("post:actors")
def create_actor(payload):
    data = request.get_json()
    try:
        if 'name' in data and 'age' in data and 'gender' in data:
            actor = Actors(name=data.get('name'), age=data.get(
                'age'), gender=data.get('gender'))
            actor.insert()
            return jsonify({"success": True, "actor": actor.format()})
        else:
            return jsonify({"success": False})
    except:
        abort(500)


@app.route('/actors/<int:id>', methods=["PATCH"])
@requires_auth("patch:actors")
def edit_actor(payload, id):
    data = request.get_json()
    actor = Actors.query.get(id)
    if not actor:
        abort(404)
    try:
        if 'name' in data and 'age' in data and 'gender' in data:
            actor.name = data.get('name')
            actor.age = data.get('age')
            actor.gender = data.get('gender')
            actor.update()
            return jsonify({"success": True, "actor": actor.format()})
        else:
            return jsonify({"success": False})
    except:
        abort(500)


@app.route('/actors/<int:id>', methods=["DELETE"])
@requires_auth("delete:actors")
def delete_actor(payload, id):
    actor = Actors.query.get(id)
    if actor:
        actor.delete()
        return jsonify({"success": True, "id": id})
    else:
        abort(422)


@app.route('/movies')
@requires_auth("get:movies", methods=["GET"])
def get_movies(payload):
    movies = Movies.query.all()
    return jsonify({"success": True, "movies": [movie.format() for movie in movies]})


#MOVIES
@app.route('/movies', methods=["POST"])
@requires_auth("post:movies")
def create_movie(payload):
    data = request.get_json()
    try:
        if 'title' in data and 'release_date' in data:
            movie = Movies(title=data.get('title'),
                           release_date=data.get('release_date'))
            movie.insert()
            return jsonify({"success": True, "movie": movie.format()})
        else:
            return jsonify({"success": False})
    except:
        abort(500)


@app.route('/movies/<int:id>', methods=["PATCH"])
@requires_auth("patch:movies")
def edit_movie(payload, id):
    data = request.get_json()
    movie = Movies.query.get(id)
    if not movie:
        abort(404)
    try:
        if 'title' in data and 'release_date' in data:
            movie.title = data.get('title')
            movie.release_date = data.get('release_date')
            movie.update()
            return jsonify({"success": True, "movie": movie.format()})
        else:
            return jsonify({"success": False})
    except:
        abort(500)


@app.route('/movies/<int:id>', methods=["DELETE"])
@requires_auth("delete:movies")
def delete_movie(payload, id):
    movie = Movies.query.get(id)
    if movie:
        movie.delete()
        return jsonify({"success": True, "id": id})
    else:
        abort(422)


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "UNPROCESSABLE"
    }), 422


@app.errorhandler(404)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "RESOURCE NOT FOUND"
    }), 404


@app.errorhandler(AuthError)
def handle_auth_error(error):
    return jsonify({
        "success": False,
        "message": "AUTHENTICATION ERROR"
    })


# Run the app
if __name__ == '__main__':
    app.run(debug=True)
