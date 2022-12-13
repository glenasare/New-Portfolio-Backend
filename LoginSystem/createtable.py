
#Creating table as per requirement
createTable ='''CREATE TABLE USERS(
    id serial not null primary key,
    first_name varchar(20) NOT NULL,
    last_name varchar(20) NOT NULL,
    email varchar(30), password varchar(355) UNIQUE NOT NULL,login_name varchar(30) NOT NULL
)'''
print("Table created successfully........")