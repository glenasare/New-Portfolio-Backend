from datetime import datetime, timedelta

from users import User
from flask import Flask, request, g, jsonify, make_response, session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from flask_cors import CORS

import config

app = Flask(__name__)

CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.secret_key = '1234'
app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'

payload = {"data": [], "aud": ["urn:foo", "urn:bar"]}
encoded_jwt = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
print(encoded_jwt)


@app.before_request
def make_session_permanent():
    app.permanent_session_lifetime = timedelta(minutes=30)


def load_user():
    if 'token' in session:
        g.user = session["token"]


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # print(current_user) # current_user = (session["token"])

        try:
            if 'token' in session:
                user = session['token']
                return {"message": " You are already logged in", 'token': user}
        except KeyError:
            return 'Unauthorized Access!', 401
        return f(*args, **kwargs)

    return decorated


@app.route('/', methods=['GET'])
def home():
    if 'token' in session:
        token = session['token']
        return jsonify({'message': 'You are already logged in', 'token': token})
    else:
        resp = jsonify({'message': 'Unauthorized'})
        resp.status_code = 401
        return resp


@app.route('/register', methods=['POST'])
def register():
    if 'token' in session:
        token = session['token']
        return jsonify({'message': 'You are already logged in', 'email': token})

    if request.method == 'POST':
        email = request.json.get("email")
        first_name = request.json.get('first_name')
        last_name = request.json.get('last_name')
        login_name = request.json.get('login_name')
        password = request.json.get('password')

        check_email = User.load_from_db_by_email(email)


        user = User(email=email, first_name=first_name, last_name=last_name, login_name=login_name,
                    password=password)
        if User.load_from_db_by_email(email):
            return "User already exist"
        else:
            user.set_password(password)
            user.save_to_db()

        resp = jsonify({'message': 'You have Registered Successfully'})
        resp.status_code = 200
        return resp


@app.route('/users', methods=['GET'])
def get_all_users():
    if 'token' in session:
        token = session['token']
        return User.load_all_users()
    else:
        resp = jsonify({'message': 'Unauthorized'})
        resp.status_code = 401
        return resp


@app.route('/login', methods=['POST'])
def login():
    global session

    data = request.get_json()
    _email = data['username']
    _password_hash = data['password']

    if 'token' in session:
        _token = session['token']
        message = " You are already logged in"

        return make_response(jsonify({"message": message}), 202)
    else:
        if _email and _password_hash:

            # check user exists
            user = User.load_from_db_by_email(_email)

            # password_hash = user['password']
            #
            # if user.email:
            decryptedPassword = check_password_hash(user.password, _password_hash)
            token = jwt.encode(
                {
                    "sub": user.email,
                    "iat": datetime.utcnow(),
                    "exp": datetime.utcnow() + timedelta(minutes=30)
                }, app.config['SECRET_KEY'])

            if decryptedPassword:
                session['token'] = token
                return make_response(
                    jsonify({"first_name": user.first_name, "last_name": user.last_name, "email": user.email,
                             "login_name": user.login_name})

                )
            else:
                resp = jsonify({'message': 'Bad Request - invalid password'})
                resp.status_code = 400
                return resp

            # if check_password_hash(user.password, _password_hash):
            #     token = jwt.encode(
            #         {
            #                 "sub": user.email,
            #                 "iat": datetime.utcnow(),
            #                 "exp": datetime.utcnow() + timedelta(minutes=30)
            #         }, app.config['SECRET_KEY'])
            #
            #     session['token'] = token

        # else:
        #     resp = jsonify({'message': 'Bad Request - invalid credendtials'})
        #     resp.status_code = 400
        #     return resp

    # validate the received values


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.pop('token', None)
    session.clear()

    return make_response('You have been logged out successfully', 202)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
