import logging
from functools import wraps

import flask_jwt_extended
import flask_restful
from flask import make_response, request
from flask_jwt_extended.exceptions import JWTExtendedException
from jwt import PyJWTError

import monkey_island.cc.environment.environment_singleton as env_singleton
import monkey_island.cc.resources.auth.user_store as user_store
from monkey_island.cc.resources.auth.credential_utils import (
    get_username_password_from_request,
    password_matches_hash,
)
from monkey_island.cc.services.authentication import AuthenticationService

logger = logging.getLogger(__name__)


def init_jwt(app):
    user_store.UserStore.set_users(env_singleton.env.get_auth_users())
    _ = flask_jwt_extended.JWTManager(app)
    logger.debug(
        "Initialized JWT with secret key that started with " + app.config["JWT_SECRET_KEY"][:4]
    )


class Authenticate(flask_restful.Resource):
    """
    Resource for user authentication. The user provides the username and password and we
    give them a JWT.
    See `AuthService.js` file for the frontend counterpart for this code.
    """

    def post(self):
        """
        Example request:
        {
            "username": "my_user",
            "password": "my_password"
        }
        """
        username, password = get_username_password_from_request(request)

        if _credentials_match_registered_user(username, password):
            AuthenticationService.unlock_datastore_encryptor(username, password)
            access_token = _create_access_token(username)
            return make_response({"access_token": access_token, "error": ""}, 200)
        else:
            return make_response({"error": "Invalid credentials"}, 401)


def _credentials_match_registered_user(username: str, password: str) -> bool:
    user = user_store.UserStore.username_table.get(username, None)

    if user and password_matches_hash(password, user.secret):
        return True

    return False


def _create_access_token(username):
    access_token = flask_jwt_extended.create_access_token(
        identity=user_store.UserStore.username_table[username].id
    )
    logger.debug(f"Created access token for user {username} that begins with {access_token[:4]}")

    return access_token


# See https://flask-jwt-extended.readthedocs.io/en/stable/custom_decorators/
def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            flask_jwt_extended.verify_jwt_in_request()
            return fn(*args, **kwargs)
        # Catch authentication related errors in the verification or inside the called function.
        # All other exceptions propagate
        except (JWTExtendedException, PyJWTError) as e:
            return make_response({"error": f"Authentication error: {str(e)}"}, 401)

    return wrapper
