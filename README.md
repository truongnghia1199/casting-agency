
# Casting Agency
  The Casting Agency models a company that is responsible for creating movies and managing and assigning actors to those movies. You are an Executive Producer within the company and are creating a system to simplify and streamline your process.

# Model:
  - Movies with attributes title and release date
  - Actors with attributes name, age and gender

# API Endpoint:
  - `GET '/actors'`: Get list actor
  - `POST '/actors'`: Create new actor. Example: ```{
      "name": "actor1",
      "age": 20,
      "gender": "nam"
  }```
  - `PATCH '/actors/<int:id>'`: Edit actor. Example: ```{
      "name": "actor1",
      "age": 20,
      "gender": "nam"
  }```
  - `DELETE '/actors/<int:id>'`: Delete actor

  - `GET '/movies'`: Get list movie
  - `POST '/movies'`: Create new movie. Example: ```{
      "title": "movie1",
      "release_date": "05/11/2024"
  }```
  - `PATCH '/movies/<int:id>'`: Edit movie. Example: ```{
      "title": "movie1",
      "release_date": "05/11/2024"
  }```
  - `DELETE '/movies/<int:id>'`: Delete actor

# Roles:
  - Casting Assistant
    - Can view actors and movies
  - Casting Director
    - All permissions a Casting Assistant has and…
    - Add or delete an actor from the database
    - Modify actors or movies
  - Executive Producer
    - All permissions a Casting Director has and…
    - Add or delete a movie from the database

# Tests:
  - One test for success behavior of each endpoint
  - One test for error behavior of each endpoint
  - At least two tests of RBAC for each role

# Example token:
# casting-agency
# casting-agency
