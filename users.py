import oauth2
import json

import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from serverconnection import conn
from psycopg2 import Error


class User:
    def __init__(self, password, email, first_name, last_name, login_name):
        self.password = password
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.login_name = login_name

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def save_to_db(self, conn=None):

        try:
            # Creating a cursor object using the cursor() method
            cursor = conn.cursor()

            cursor.execute('INSERT INTO users(first_name, last_name, email ,password,login_name) VALUES (%s, %s, %s, '
                           '%s, '
                           '%s)',
                           (self.first_name, self.last_name, self.email, self.password, self.login_name))
            # Commit your changes in the database
            conn.commit()
            print("Records inserted........")
        except (Exception, Error) as error:
            print("Error while connecting to PostgreSQL", error)
        finally:
            if conn:
                cursor.close()
                conn.close()
                print("PostgreSQL connection is closed")

    @classmethod
    def load_from_db_by_email(cls, email):

        global cursor
        try:
            # Creating a cursor object using the cursor() method
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
            user_data = cursor.fetchone()
            if user_data:
                return cls(first_name=user_data[1], last_name=user_data[2],
                           email=user_data[3], login_name=user_data[5], password=user_data[4])
            # Commit your changes in the database
            conn.commit()
            print("Records Retrieved....")
        except (Exception, Error) as error:
            print("Error while connecting to PostgreSQL", error)
        finally:
            if conn:
                cursor.close()
                conn.close()
                print("PostgreSQL connection is closed")

    @classmethod
    def load_all_users(cls):
        conn.autocommit = True
        # Creating a cursor object using the cursor() method
        cursor = conn.cursor()
        cursor.execute('SELECT first_name,last_name,email FROM users ')
        user_data = cursor.fetchall()
        return user_data

        # Commit your changes in the database
        conn.commit()
        print("Records Retrieved....")
        # Closing the connection
        conn.close()
