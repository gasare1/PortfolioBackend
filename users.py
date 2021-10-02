from database import CursorFromConnectionFromPool
import oauth2
import json
from werkzeug.security import generate_password_hash, check_password_hash



class User:
    def __init__(self, password_hash ,email,firstname,lastname):
        self.password_hash = password_hash
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        

    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
     
    def check_password(self,password):
        return check_password_hash(self.password_hash,password)

    def __repr__(self):
        return "<User {}>".format(self.email)

    def save_to_db(self):
        with CursorFromConnectionFromPool() as cursor:
            cursor.execute('INSERT INTO portfoliousers(username,password_hash) VALUES (%s, %s)',
                           (self.username,self.password_hash))
    def save_to_db_maillist(self):
        with CursorFromConnectionFromPool() as cursor:
            cursor.execute('INSERT INTO portfoliousers (firstname, lastname, email) VALUES (%s, %s, %s)',
                           (self.email,self.firstname,self.lastname))
    def save_to_db_portfolio(self):
        with CursorFromConnectionFromPool() as cursor:
            cursor.execute('INSERT INTO glenasare1(firstname, lastname, email ,password_hash) VALUES (%s, %s, %s, %s)',
                           (self.firstname,self.lastname,self.email,self.password_hash))                      
    @classmethod
    def load_from_db_by_email(cls, email):
        with CursorFromConnectionFromPool() as cursor:
            cursor.execute('SELECT * FROM portfoliousers WHERE email=%s', (email,))
            user_data = cursor.fetchone()
            if user_data:
                return cls(firstname=user_data[1], lastname=user_data[2],
                           email=user_data[3],license = user_data[4],address=user_data[5],password_hash=user_data[3] )
    @classmethod
    def load_from_db_by_username(cls, username):
        with CursorFromConnectionFromPool() as cursor:
            cursor.execute('SELECT * FROM adminlogin WHERE username=%s', (username,))
            user_data = cursor.fetchone()
            if user_data:
                return cls(username=user_data[1], password_hash=user_data[2] )
    @classmethod
    def load_from_db_by_usernames(cls, email):
        with CursorFromConnectionFromPool() as cursor:
            cursor.execute('SELECT * FROM glenasare1  WHERE email=%s', (email,))
            user_data = cursor.fetchone()
            if user_data:
                return cls(email=user_data[1], password_hash=user_data[2],firstname=user_data[3],lastname=user_data[4] )