import hashlib
import string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response, redirect, render_template
from flask_jwt_extended import (
    JWTManager, jwt_required,
    get_jwt_identity
)
from serverconnection import connect_to_database
from flask_cors import CORS
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from twilio.rest import Client
import random

import os

app = Flask(__name__, template_folder='templates')
cors = CORS(app, origins=['http://localhost:3000', "https://my-app-flaskk.herokuapp.com", "https://api.glenasare.com"])





class MobileVerificationForm(FlaskForm):
    mobile_number = StringField('Mobile Number')
    submit = SubmitField('Send Code')


class CodeVerificationForm(FlaskForm):
    code = StringField('Verification Code')
    submit = SubmitField('Verify')


def generate_verification_code():
    # generate a random 6-digit verification code
    return ''.join(random.choices(string.digits, k=6))


verification_code = generate_verification_code()


@app.route('/', methods=['GET'])
def home():
    conn = connect_to_database()
    cur = conn.cursor()

    cur.execute("SELECT * FROM userinfo WHERE access_token=%s", (verification_code,))
    user = cur.fetchone()
    if not user:
        return make_response({"message": "Please Login"}, 401)
    return make_response({"message": "Already Logged In"}, 200)


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
    cur.execute("SELECT * FROM userinfo WHERE email=%s", (email,))
    user = cur.fetchone()

    if user is not None:
        return jsonify({"msg": "Login name already exists"}), 400

    # Insert the new user into the database
    cur.execute("INSERT INTO userinfo (first_name, last_name, email, login_name, password) VALUES (%s, %s, %s, %s, %s)",
                (first_name, last_name, email, login_name, hashed_password))
    conn.commit()

    return jsonify({"msg": "User created successfully"}), 201
    conn.close()


user_id = ""


# Function to log in a user
@app.route('/login', methods=['POST'])
def login():
    global resp, user_id

    # Get the data from the request
    data = request.get_json()
    email = data['email']
    password = data['password']
    conn = connect_to_database()
    cur = conn.cursor()

    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Check if the username and password are correct
    cur.execute("SELECT * FROM userinfo WHERE lower(email) = lower(%s) AND ""password=%s", (email, hashed_password))
    user = cur.fetchone()

    response = make_response("login successful")
    response.headers["Access-Control-Allow-Origin"] = "https://glenasare.com"

    if user is None:
        return jsonify({"msg": "Invalid username or password"}), 401

    # Create a JSON Web Token with an expiration time of 30 minutes
    if user:
        user_id = user[0]
        return redirect("/verify-mobile", 302)

    if not user:
        return {"message": "User not found"}, 404

    return resp, 200


def send_sms(mobile_number, verification_code):
    # Your Account Sid and Auth Token from twilio.com/console
    account_sid = os.getenv('account_sid')
    auth_token = os.getenv('auth_token')
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body="Your verification code is: " + verification_code,
        from_='+12059474196',
        to=mobile_number
    )


@app.route("/verify-mobile", methods=['GET', 'POST'])
def verify_mobile():
    global verification_code
    form = MobileVerificationForm()

    if form.validate_on_submit():
        mobile_number = form.mobile_number.data

        if mobile_number:
            send_sms(mobile_number, verification_code)
            return redirect("/verify-code", code=302)

    return render_template('verify_mobile.html', form=form)


@app.route("/verify-code", methods=["GET", 'POST'])
def verify_code():
    form = CodeVerificationForm()
    entered_code = form.code.data

    conn = connect_to_database()
    cur = conn.cursor()
    if form.validate_on_submit():

        # compare entered code with the generated code to verify mobile number
        if entered_code == verification_code:
            # mobile number is verified

            access_code = verification_code

            cur.execute("SELECT * FROM userinfo WHERE access_token=%s", (verification_code,))
            user = cur.fetchone()
            if user is None:
                cur.execute("UPDATE userinfo SET access_token = %s where id = %s ", (access_code, user_id))
                conn.commit()
            else:
                cur.execute("UPDATE userinfo SET access_token = %s where id=%s ", (access_code, user_id))
                conn.commit()

            return redirect("http://glenasare.com/", 200)
        else:
            # entered code is incorrect
            return redirect("/verify-mobile", 401)
    return render_template('verify_code.html', form=form)


@app.route("/user", methods=["GET"])
def get_user():
    # print(user_info)
    # return str(user_info)
    conn = connect_to_database()
    cur = conn.cursor()

    cur.execute("SELECT * FROM userinfo WHERE access_token=%s", (verification_code,))
    user = cur.fetchone()
    if not user:
        return make_response({"message"}, "Invalid Token Please Login", 401)

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


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    conn = connect_to_database()
    cur = conn.cursor()

    userid = str(user_id)

    cur.execute("UPDATE userinfo SET access_token = null where id = %s ", (userid,))
    conn.commit()

    resp = make_response({"message": "You have been logged out successfully"}, 202)

    return resp


if __name__ == '__main__':
    app.run()
