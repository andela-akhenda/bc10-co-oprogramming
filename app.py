from flask import Flask, render_template, request, url_for, redirect, make_response
import pyrebase

app = Flask(__name__)

config = {
  "apiKey": "AIzaSyDrCeJ-2yN_iB8znyDeG8ZRS39BiWdlcxE",
  "authDomain": "co-oprogramming.firebaseapp.com",
  "databaseURL": "https://co-oprogramming.firebaseio.com",
  "storageBucket": "co-oprogramming.appspot.com"
}

firebase = pyrebase.initialize_app(config) 

email="akhenda@gmail.com"
password="123456789"

auth = firebase.auth()
user = auth.sign_in_with_email_and_password(email, password)


@app.route('/',  methods=['GET', 'POST'])
def index():
    return render_template('index.html')    



if __name__ == '__main__':
	app.run(host='127.0.0.1', port=5555, debug=True)