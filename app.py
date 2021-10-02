from users import User
from flask import Flask, render_template, session, redirect, request, url_for, g,jsonify,make_response,flash
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
from database import Database
import jwt
from functools import wraps
import psycopg2
import psycopg2.extras
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
app.secret_key = '1234'
app.config['SECRET_KEY']='004f2af45d3a4e161a7dd2d17fdae47f'

DB_HOST = "chunee.db.elephantsql.com"
DB_NAME = "fvfkyplb"
DB_USER = "fvfkyplb"
DB_PASS = "xNtNNQZjhMksOec28bJH_g_gisWeZAcZ"
Database.initialise(dbname=DB_NAME, user=DB_USER,
                        password=DB_PASS, host=DB_HOST)
db = Database
#session_manager = PickleSession()


     
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER,
                        password=DB_PASS, host=DB_HOST) 

encoded_jwt = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
payload = {"some": "payload", "aud": ["urn:foo", "urn:bar"]}
print(encoded_jwt)
session={'logins':0}
@app.before_request
def load_user():
    if 'email' in session:
        g.user = User.load_from_db_by_usernames(session['email'])

@app.route('/')
def home():
    pass_hash = generate_password_hash('cairocoders')
    if 'email' in session:
        email = session['email']
        return jsonify({'message' : 'You are already logged in', 'email' : email})
    else:
        resp = jsonify({'message' : 'Unauthorized'})
        resp.status_code = 401
        return resp

@app.route('/register', methods=['POST', 'GET'])
def register():
    if 'email' in session:
        email = session['email']
        return jsonify({'message' : 'You are already logged in', 'email' : email})

    if request.method == 'POST':
        
        email = request.json.get("email")
        firstname = request.json.get('firstname')
        lastname = request.json.get('lastname')
        license = request.json.get('license')
        address = request.json.get('address')
        password_hash = request.json.get('password_hash')

       

        user = User(email=email, firstname=firstname,lastname=lastname,license=license,address=address, password_hash=password_hash)
        user.set_password(password_hash)
        user.save_to_db()
        
        resp = jsonify({'message' : 'You have Registered Successfully'})
        resp.status_code = 200
        return resp
@app.route('/adminregister', methods=['POST', 'GET'])
def registeradmin():
    if 'email' in session:
        _email = session['email']
        return jsonify({'message' : 'You are already logged in', 'email' : _email})

    if request.method == 'POST':
    
            _email = request.json.get("email")
            _password_hash = request.json.get('password_hash')

        
        
            user = User(email =_email, password_hash = _password_hash)
            user.set_password(_password_hash)
            user.save_to_db()
            
            resp = jsonify({'message' : 'You have Registered Successfully'})
            resp.status_code = 200
            return resp
@app.route('/portfolioregister', methods=['POST', 'GET'])
def registerportfolio():
    if 'email' in session:
        _email = session['email']
        return jsonify({'message' : 'You are already logged in', 'email' : _email})

    if request.method == 'POST':
    
            _email = request.json.get("email")
            _password_hash = request.json.get('password_hash')
            _firstname = request.json.get('firstname')
            _lastname = request.json.get('lastname')

        
        
            user = User(email=_email, password_hash = _password_hash,firstname=_firstname,lastname=_lastname)
            user.set_password(_password_hash)
            user.save_to_db_portfolio()
            
            resp = jsonify({'message' : 'You have Registered Successfully'})
            resp.status_code = 200
            return resp
        
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(lastname = data['lastname'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated

@app.route('/user', methods =['GET'])
@token_required
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'lastname': user.lastname,
            'firstname' : user.firstname,
            'email' : user.email
        })
  
    return jsonify({'users': output})
@app.route('/login', methods=['POST', 'GET'])
def login():
    global session
    if 'email' in session:
        _email = session['email']
        _firstname = session['firstname']
        _lastname = session['lastname']
       
        return jsonify({'message' : 'You are already logged in', 'email' : _firstname })
    
    _json = request.json
    _email = _json['email']
    _password_hash = _json['password_hash']
    print(_password_hash)
    # validate the received values
    if _email and _password_hash:
        #check user exists          
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
          
        sql = "SELECT * FROM glenasare1 WHERE email=%s"
        sql_where = (_email,)
          
        cursor.execute(sql, sql_where)
        row = cursor.fetchone()
        email = row['email']
        firstname = row['firstname']
        lastname = row['lastname']
        password_hash = row['password_hash']
      
        if row:
            if check_password_hash(password_hash, _password_hash):
                token = jwt.encode(payload, "secret")
                decoded = jwt.decode(token, "secret", audience="urn:foo", algorithms=["HS256"])
                session['email'] = email
                session['firstname'] = firstname
                session['lastname'] = lastname
               
                
                return make_response(jsonify({'message' : 'You are logged in successfully'},lastname )
                )
            else:
                resp = jsonify({'message' : 'Bad Request - invalid password'})
                resp.status_code = 400
                return resp
    else:
        resp = jsonify({'message' : 'Bad Request - invalid credendtials'})
        resp.status_code = 400
        return resp
@app.route('/signup', methods =['POST'])
def signup():
    # creates a dictionary of the form data
    
  
    # gets name, email and password
    email = request.json.get("email")
    firstname = request.json.get('firstname')
    lastname = request.json.get('lastname')
    license = request.json.get('license')
    address = request.json.get('address')
    password_hash = request.json.get('password_hash')
  
    # checking for existing user
    user = User.load_from_db_by_email(email)
    if not user:
        # database ORM object
        user = User(
            lastname = lastname,
            firstname = firstname,
            license = license,
            address = address,
            email = email,
            password_hash = generate_password_hash(password_hash)
        )
        # insert user
        user.save_to_db()
  
        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)
@app.route('/maillist', methods =['POST'])
def maillist():
    # creates a dictionary of the form data
    
  
    # gets name, email and password
    email = request.json.get("email")
    firstname = request.json.get('firstname')
    lastname = request.json.get('lastname')
 
  

    # checking for existing user
    user = User.load_from_db_by_email(email)
    if not user:
        # database ORM object
        user = User(
            lastname = lastname,
            firstname = firstname,
            email = email,
        )
        # insert user
        user.save_to_db_maillist()
  
        return make_response('Successfully registered.', 201)
    else:
            # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)
@app.route('/logout')
def logout():
    session.clear()
    return make_response('You have been logged out successfully', 202)
if __name__ == "__main__":
    app.run(debug=False)