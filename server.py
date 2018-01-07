# imports
from flask import Flask, render_template, request, redirect, flash, session
import re
from mysqlconnection import MySQLConnector
import md5
import os, binascii

app = Flask(__name__)
app.secret_key = "the wall is scary"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
mysql = MySQLConnector(app, 'walldb')
# print mysql.query_db("SELECT * FROM users")

def validName(string):
    for char in string:
        if char.isdigit():
            return False
    return True

# root route
@app.route('/')
def index():
    return render_template('login.html')

#registration
@app.route('/register', methods=['POST'])
def registerlogin():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    valid = True
    password_confirm = request.form['password_confirm']

    # verfying that all fields are not empty
    if len(first_name) < 1 or len(last_name) < 1 or len(email) < 1 or len(password) < 1 or len(password_confirm) < 1:
        flash("All fields are required", "red")
        valid = False
        print valid

    #verfying first and last name
    if not validName(first_name) or not validName(last_name):
        flash("First Name and Last Name cannot contain numbers", "red")
        valid = False
        print valid
    if len(first_name) < 2 or len(last_name) < 2:
        flash("First Name and Last Name must contain at least two letters", "red")
        valid = False
        print valid
    
    # verifying email
    if not EMAIL_REGEX.match(email):
        flash("Invalid email", "red")
        valid = False
        print valid
    query = "SELECT * FROM users WHERE email = :email"
    data = {"email": email}
    exists = mysql.query_db(query,data)
    if exists:
        flash("email is already registered", "red")
        valid = False

    #verifying password
    if len(password) <= 7:
        flash("Password must be at least 8 characters", "red")
        valid = False
        print valid
    if password != password_confirm:
        flash("Passwords must match", "red")
        valid = False
        print valid
    
    # registration success/insert user into database 
    if valid:
        flash("Registration successful", "green")
        salt =  binascii.b2a_hex(os.urandom(15))
        hashed_pw = md5.new(password + salt).hexdigest()
        print password, salt, hashed_pw
        query = "INSERT INTO users (first_name, last_name, email, hashed_pw, salt, created_at, updated_at) VALUES(:first_name, :last_name, :email, :hashed_pw, :salt, NOW(), NOW())"
        data = {
            'first_name': request.form['first_name'], 
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'hashed_pw': hashed_pw,
            'salt': salt
        }
        mysql.query_db(query, data)
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    login_email = request.form['login_email']
    login_password = request.form['login_password']
    query = "SELECT * FROM users WHERE email = :email"
    data = {"email": login_email}
    user = mysql.query_db(query,data)
    # print user[0]["salt"]
    if not user:
        flash("There is no account with that email address", "red")
        return redirect('/')
    else:
        salt =  user[0]["salt"]
        hashed_pw = md5.new(login_password + salt).hexdigest()
        print hashed_pw, user[0]['hashed_pw']
        if user[0]['hashed_pw'] == hashed_pw:
            session_query = "SELECT * FROM users WHERE users.email = :email"
            query_data = {'email': login_email}
            login_firstnm = mysql.query_db(session_query, query_data)[0]['first_name']
            session['login_firstnm'] = login_firstnm
            user_id = mysql.query_db(session_query, query_data)[0]['id']
            session["id"] = user_id
            print login_firstnm
            return redirect('/wall')

#wall
@app.route ('/wall')
def wall():
    print session
    if 'id' in session:
        text = "currently logged in"
    else: 
        text = "please log in"
    all_messages_query = "SELECT CONCAT(first_name, ' ', last_name) AS full_name, DATE_FORMAT(messages.created_at, '%M %d %Y') AS day, message, messages.id FROM messages JOIN users ON users.id = messages.user_id ORDER BY messages.id DESC;"
    all_comments_query = "SELECT CONCAT(first_name, ' ', last_name) AS full_name, DATE_FORMAT(comments.created_at, '%M %d %Y')AS day, comment, message_id FROM comments JOIN users ON users.id = comments.user_id;"
    all_messages = mysql.query_db(all_messages_query)
    all_comments = mysql.query_db(all_comments_query)
    print all_comments
    return render_template('wall.html', text = text, all_messages = all_messages, all_comments = all_comments)

# messages
@app.route('/message', methods=['POST'])
def messages():
    message = request.form['message']
    query = "INSERT INTO messages (message, created_at, updated_at, user_id) VALUES(:message, NOW(), NOW(), :user_id)"
    data = {
        'message': request.form['message'],
        'user_id': session['id']
    }
    print ['message']
    mysql.query_db(query, data)
    return redirect('/wall')

#comments
@app.route('/comment/<message_id>', methods=['POST'])
def comment(message_id):
    comment = request.form['comment']
    query = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id) VALUES(:comment, NOW(), NOW(), :user_id, :message_id)"
    data = {
        'comment': comment,
        'user_id': session['id'],
        'message_id': message_id
    }
    mysql.query_db(query, data)
    return redirect('/wall')

# log out
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect('/')

app.run(debug=True)