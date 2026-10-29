#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

user_schema = UserSchema()
recipe_schema = RecipeSchema()
recipes_schema = RecipeSchema(many=True)


def unauthorized():
    return {'errors': ['Unauthorized. Please log in.']}, 401


def current_user():
    """Return the logged-in User, or None."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.session.get(User, user_id)


class Signup(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')

        errors = []
        if not username:
            errors.append('Username must be present.')
        if not password:
            errors.append('Password must be present.')
        if errors:
            return {'errors': errors}, 422

        try:
            user = User(
                username=username,
                image_url=data.get('image_url'),
                bio=data.get('bio'),
            )
            user.password_hash = password

            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['Username is already taken.']}, 422
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        session['user_id'] = user.id
        return user_schema.dump(user), 201


class CheckSession(Resource):
    def get(self):
        user = current_user()
        if not user:
            return unauthorized()
        return user_schema.dump(user), 200


class Login(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter(User.username == username).first()

        if user and password and user.authenticate(password):
            session['user_id'] = user.id
            return user_schema.dump(user), 200

        return {'errors': ['Invalid username or password.']}, 401


class Logout(Resource):
    def delete(self):
        if not session.get('user_id'):
            return unauthorized()
        session['user_id'] = None
        return {}, 204


class RecipeIndex(Resource):
    def get(self):
        user = current_user()
        if not user:
            return unauthorized()
        recipes = Recipe.query.all()
        return recipes_schema.dump(recipes), 200

    def post(self):
        user = current_user()
        if not user:
            return unauthorized()

        data = request.get_json() or {}

        try:
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user.id,
            )
            db.session.add(recipe)
            db.session.commit()
        except (IntegrityError, ValueError) as e:
            db.session.rollback()
            if isinstance(e, ValueError):
                return {'errors': [str(e)]}, 422
            return {'errors': ['Recipe is not valid.']}, 422

        return recipe_schema.dump(recipe), 201


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
