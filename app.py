import psycopg2
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, make_response
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from serverconnection import connect_to_database
from flask_cors import CORS, cross_origin
from jwt import encode, ExpiredSignatureError, InvalidTokenError, decode
from functools import wraps

app = Flask(__name__)
cors = CORS(app, supports_credentials=True)
app.config['JWT_SECRET_KEY'] = 'super secret'
app.config["SESSION_PERMANENT"] = False
jwt = JWTManager(app)

# Set the secret key for the session
app.secret_key = "1234"


@app.before_request
def make_session_permanent():
    app.permanent_session_lifetime = timedelta(minutes=30)


def load_user():
    if "session" in session:
        user = session["session"]
        return user


@app.route('/', methods=['GET'])
def home():
    if "session" in session:
        token = session["session"]
        return jsonify({'message': 'You are already logged in', 'token': token})
    else:
        resp = jsonify({'message': 'Unauthorized'})
        resp.status_code = 401
        return resp


# Function to register a new user
@app.route('/register', methods=['POST'])
def register():
    # Get the data from the request
    data = request.get_json()
    first_name = data['first_name']
    last_name = data['last_name']
    email = data['email']
    login_name = data['login_name']
    password = data['password']

    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    conn = connect_to_database()
    cur = conn.cursor()

    # Check if the login name already exists
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    if user is not None:
        return jsonify({"msg": "Login name already exists"}), 400

    # Insert the new user into the database
    cur.execute("INSERT INTO users (first_name, last_name, email, login_name, password) VALUES (%s, %s, %s, %s, %s)",
                (first_name, last_name, email, login_name, hashed_password))
    conn.commit()

    return jsonify({"msg": "User created successfully"}), 201
    conn.close()


def generate_jwt(user_id):
    try:
        payload = {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(hours=24)
        }

        jwt_token = encode(payload, app.secret_key, algorithm="HS256")

        return jwt_token
    except Exception as error:
        print("Error while generating JWT", error)


# Function to log in a user
@app.route('/login', methods=['POST'])
def login():
    # Check if there is already an access token in the session
    global resp

    if "session" in session:
        resp = make_response({"message": "User already Logged in"})
        return resp, 400

    # Get the data from the request
    data = request.get_json()
    email = data['email']
    password = data['password']
    conn = connect_to_database()
    cur = conn.cursor()

    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Check if the username and password are correct
    cur.execute("SELECT * FROM users WHERE lower(email) = lower(%s) AND ""password=%s", (email, hashed_password))
    user = cur.fetchone()

    if user is None:
        return jsonify({"msg": "Invalid username or password"}), 401

    # Create a JSON Web Token with an expiration time of 30 minutes

    jwt_token = generate_jwt(user[0])

    session["session"] = jwt_token

    resp = make_response({"message": "You've been successfully logged in"})

    if not user:
        return {"message": "User not found"}, 404

    return resp, 200


@app.route("/user", methods=["GET"])
def get_user():
    jwt_token = session["session"]



    try:
        payload = decode(jwt_token, app.secret_key, algorithms="HS256")
        user_id = payload["user_id"]
    except:
        if InvalidTokenError:
            return {"message": "Invalid Toke"}
        if ExpiredSignatureError:
            return {"message": "Token Expired Login Again"}

    conn = connect_to_database()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, email, first_name, last_name FROM users WHERE id = %s", (user_id,)
    )
    user = cur.fetchone()
    return [{
               "id": user[0],
               "first_name": user[2],
               "last_name": user[3],
               "email": user[1],

           }], 200


# Function to protect a route with JWT authentication
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Get the user's identity from the JWT
    current_user = get_jwt_identity()

    return jsonify(logged_in_as=current_user), 200


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    resp = make_response({"message": "You have been logged out successfully"}, 202)
    resp.delete_cookie('session')
    session.pop('session', None)
    session.clear()

    return resp


if __name__ == '__main__':
    app.run()
