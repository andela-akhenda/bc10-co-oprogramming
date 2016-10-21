from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, send, emit
import pyrebase
import flask_login
import json
import time
import sys

app = Flask(__name__)
socketio = SocketIO(app)
app.secret_key = 'kPZZ5P5Oap5euxpujz3D'
app.config['SECRET_KEY'] = 'kPZZ5P5Oap5euxpujz3D!'
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = u"You need to login to use Co-oprogramming"
login_manager.login_message_category = "info"

config = {
  "apiKey": "AIzaSyDrCeJ-2yN_iB8znyDeG8ZRS39BiWdlcxE",
  "authDomain": "co-oprogramming.firebaseapp.com",
  "databaseURL": "https://co-oprogramming.firebaseio.com",
  "storageBucket": "co-oprogramming.appspot.com"
}
firebase = pyrebase.initialize_app(config)
db = firebase.database()
fb_auth = firebase.auth()
ace_sess_id = ""

class User(flask_login.UserMixin):
    # self , email , expiresIn, refreshToken, idToken, registered, displayName, localId
    def __init__(self , email, localId, idToken):
        self.email = email
        self.idToken = idToken
        self.localId = localId

    def get_id(self):
        return self.idToken

    @staticmethod
    def get(idToken):
        """
        A Static method to search the Firebase database and see if idToken exists.  If it 
        does exist then return a User Object.  If not then return None as 
        required by Flask-Login. 
        """
        try:
            is_user_there = fb_auth.get_account_info(idToken)
            if is_user_there:
                for user in is_user_there['users']:
                    # print(user, file=sys.stderr)
                    if user['email']:
                        return User(user['email'], user['localId'], idToken)
        except:
            return None

@login_manager.user_loader
def user_loader(idToken):
    return User.get(idToken)

@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    password = request.form.get('pw')
    print(email, file=sys.stderr)
    print(password, file=sys.stderr)
    try:
        fb_user = fb_auth.sign_in_with_email_and_password(email, password)
        user = User(fb_user['email'], fb_user['localId'], fb_user['idToken'])
        return user
    except:
        return

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        email = request.form['email']
        password = request.form['pw']
        print(email, file=sys.stderr)
        print(password, file=sys.stderr)
        try:
            fb_user = fb_auth.sign_in_with_email_and_password(email, password)
            if fb_user:
                user = User(fb_user['email'], fb_user['localId'], fb_user['idToken'])
                flask_login.login_user(user)
                print(user.email, file=sys.stderr)
                return redirect(url_for('index'))
        except:
            flash('Invalid Login Credentials')
            return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('reset_password.html')
    email = request.form['email']
    try:
        flash('Check your inbox for a reset link')
        return render_template('logout.html')
    except:
        flash('Unknown Error')
        return render_template('logout.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    email = request.form['email']
    pw = request.form['pw']
    fb_auth.create_user_with_email_and_password(email, pw)
    try:
        flash('Your account has been created succesfully')
        return redirect(url_for('login'))
    except:
        flash('Unknown Error')
        return redirect(url_for('signup'))

@app.route('/protected')
@flask_login.login_required
def protected():
    return 'Logged in as: ' + flask_login.current_user.localId

@app.route('/logout')
def logout():
    flask_login.logout_user()
    # flash('You have been logged out successfuly...')
    flash('LOGGED OUT')
    return render_template('logout.html')

@login_manager.unauthorized_handler
def unauthorized_handler():
    flash('You need to log in to use this service')
    return redirect(url_for('login', next=request.endpoint))




@app.route('/',  methods=['GET', 'POST'])
@flask_login.login_required
def index():
    messages = {}
    return_data = {}
    try:
        chat_history = db.child("-KUYCsj_neC3wRfl_qrA").child("chat_history").get()
        for msg in chat_history.each():
            messages[msg.key()] = msg.val()
        all_sessions = db.get()
        for sess in all_sessions.each():
            sess_data = sess.val()
            return_data[sess.key()] = {}
            return_data[sess.key()]['name'] = sess_data['session_name']
            for key in sess_data['users']:
                return_data[sess.key()]['users'] = key
    except:
        messages = {}
    return render_template('index.html', fb_api = config['apiKey'], fb_auth_domain = config['authDomain'], fb_db_url = config['databaseURL'], logged_in_user_id = flask_login.current_user.localId, logged_in_user_email = flask_login.current_user.email, messages = messages, sessions = return_data)


@app.route('/_get_session_id')
def get_session_id():
    current_session_id = request.args.get('id', default=None, type=str)
    flask_login.current_user.session_id = current_session_id
    ace_sess_id = current_session_id
    sess_name = db.child(ace_sess_id).child("session_name").get().val()
    data = {'sess_name': sess_name}
    return jsonify(data)

@app.route('/_create_new_session')
def create_new_session():
    messages = {}
    name = request.args.get('name', default=None, type=str)
    print(name, file=sys.stderr)
    # return redirect(url_for('index', sess_name=name))
    data = {"session_name": name, "invites": [0], "users": { flask_login.current_user.localId : { "name": flask_login.current_user.email } } }
    db.push(data)
    return jsonify(data)

@app.route('/_edit_session')
def edit_session():
    current_session_id = request.args.get('sess_id', default=None, type=str)
    name = request.args.get('name', default=None, type=str)
    db.child(current_session_id).update({"session_name": name})

@app.route('/_delete_session')
def delete_session():
    current_session_id = ""
    current_session_id = request.args.post('sess_id', default=None, type=str)
    print(current_session_id)
    if len(current_session_id) > 5:
        db.child(current_session_id).remove()
    response = redirect(url_for('index'), code=302)
    headers = dict(response.headers)
    # headers.update({'X-Custom-Header1': 'value1', 'X-Custom-Header2': 'value2'})
    response.headers = headers
    return response

@app.route('/_my_sessions')
def my_sessions():
    messages = {}
    try:
        current_session_id = request.args.get('sess_id', default=None, type=str)
        # all_sessions = db.child(current_session_id).order_by_child("users").equal_to(flask_login.current_user.localId).get()
        all_sessions = db.get()
        return_data = {}
        for sess in all_sessions.each():
            sess_data = sess.val()
            return_data[sess.key()] = {}
            return_data[sess.key()] ['name'] = sess_data['session_name']
            for key in sess_data['users']:
                return_data[sess.key()] ['users'] = key
        return redirect(url_for('index', sessions = return_data))
    except:
        return redirect(url_for('protected'))

# @socketio.on('connect')
# def connect_handler():
#     if current_user.is_authenticated:
#         emit('my response',
#              {'message': '{0} has joined'.format(current_user.name)},
#              broadcast=True)
#     else:
#         return False  # not allowed here

@socketio.on('message')
def handleMessage(msg):
    print('Message: ' + str(msg))
    if hasattr(flask_login.current_user, 'email'):
        if flask_login.current_user.email:
            data = { "user" : flask_login.current_user.email, "message": msg}
            try:
                db.child(ace_sess_id).child("chat_history").child(int(time.time())).update(data)
            except:
                print("Session Id not yet received", file=sys.stderr)
    send(msg, broadcast=True)



if __name__ == '__main__':
	socketio.run(app)