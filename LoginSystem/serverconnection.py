import psycopg2

newconn = psycopg2.connect(host="heffalump.db.elephantsql.com", database="fiqpyypw", user="fiqpyypw", password="Yzf2eDcMbE7cbNxOVUUHvTlIS70PlZZi")

DB_HOST = "heffalump.db.elephantsql.com"
DB_NAME = "fiqpyypw"
DB_USER = "fiqpyypw"
DB_PASS = "Yzf2eDcMbE7cbNxOVUUHvTlIS70PlZZi"

def connect_to_database():
    try:
        with newconn as conn:
            return conn
    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL", error)