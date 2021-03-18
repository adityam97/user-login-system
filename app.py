import mysql.connector
import MySQLdb.cursors
import mysql
import flask
import os
import json
import requests_oauthlib
import pandas as pd
from flask import Flask, render_template, request,session, url_for, redirect
from flask_mysqldb import MySQL
from authlib.integrations.flask_client import OAuth
from requests_oauthlib.compliance_fixes import facebook_compliance_fix
import numpy
import csv

#creating Json file and reading it
# dbJson = open(r'mysql.json')
# dbData = dbJson.read()

# #parse json
# dbInfo = json.loads(dbData)

#initializing app
app = Flask(__name__) 
oauth = OAuth(app)
fb_app = flask.Flask(__name__)



#data_frame = pd.read_csv("data.csv")

  


app.secret_key="Adi"

# db config for user login
# app.config['MYSQL_HOST'] = dbInfo["host"]
# app.config['MYSQL_USER'] = dbInfo["user"]
# app.config['MYSQL_PASSWORD'] = dbInfo["password"] 
# app.config['MYSQL_DB'] = dbInfo["DB"]
# print(app.config)

#config for social login google
app.config['SECRET_KEY'] = "THIS SHOULD BE SECRET"
app.config['GOOGLE_CLIENT_ID'] = "44649573811-g4vfucn8as4u39m24pca3v8rppddj7h4.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = "lYfaygH0WrU5r_2my_JsEMXa"

#config for social login fb
#URL = "https://679e4c83.ngrok.io"
URL = "https://userlogin-system.herokuapp.com"
# URL = "localhost:8000"

FB_CLIENT_ID = "870940717019310"
FB_CLIENT_SECRET = "51fec30fd5b076f732c89b1000e8ee0e"
FB_AUTHORIZATION_BASE_URL = "https://www.facebook.com/dialog/oauth"
FB_TOKEN_URL = "https://graph.facebook.com/oauth/access_token"
FB_SCOPE = ["email"]

# This allows us to use a plain HTTP callback
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

google = oauth.register(
    name = 'google',
    client_id = app.config["GOOGLE_CLIENT_ID"],
    client_secret = app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url = 'https://accounts.google.com/o/oauth2/token',
    access_token_params = None,
    authorize_url = 'https://accounts.google.com/o/oauth2/auth',
    authorize_params = None,
    api_base_url = 'https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs = {'scope': 'openid email profile'},
)


#initialize app
# mysql=MySQL(app)

@app.route('/', methods = ['POST', 'GET'])
def home():
    return render_template("base.html")

@app.route("/login", methods = ['POST', 'GET'])
def login():
    return render_template('login.html')

@app.route("/signup", methods = ['POST', 'GET'])
def signup():
    return render_template('signup.html')

@app.route('/success', methods = ['POST'])
def success():
    email = set()
    if request.method == 'POST':
        user = request.form['email']
        #email = request.form['email']
        password = request.form['password']
        #mycursor = mysql.connection.cursor()
        # print(email)
        # print(password)
        #mycursor.execute("select * from new_table where email = '" + user + "' and password = '" + password + "'")
        
        data = pd.read_csv("data.csv")
        #print(data)
        #mysql.connection.commit()
        print(user,password)
        for i in data["emailid"]:
            email.add(i)
        if user in email:
            pwd = data["password"].loc[data["emailid"]==user].iloc[0]
            print("password from user",str(password))
            print("password from database",str(pwd))
            if str(pwd) == password:
                return render_template("profile.html")
            else:
                login = True
                return render_template("login.html", login=login)
        else:
            lol = True
            return render_template("login.html",lol=lol)
    # return "success"


@app.route('/signsuccess', methods = ['POST','GET'])
def signsuccess():
    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']
        #mycursor = mysql.connection.cursor()
        #mycursor.execute("insert into new_table(email,password) values(%s,%s)", (email, password))
        #mysql.connection.commit()
        # print("success")
        session['user'] = email
    
        with open ("data.csv", "a") as csvfile:
            writer = csv.writer(csvfile)
            email = email
            password = password
            writer.writerow([email,password])
        
        return redirect(url_for('login'))
       
        #return render_template('success.html')
    else:
        return render_template('login.html')

    
    #data_frame.to_csv("user_data_new.csv")
@app.route("/profile",methods = ['POST', 'GET'])
def user():
    if "user" in session:
       user = session['user']
       return render_template('profile.html', content = user)
    else:
       return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user', None)
        #flash("you have been loged out!","info")
        return redirect(url_for('login'))   
    else:
        return '<p>User already logged out</p>'


#google login 
@app.route('/login/google')
def google_login():
    google = oauth.create_client('google')
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)
 

# Google authorize route
@app.route('/login/google/authorize')
def google_authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo').json()
    print(f"\n{resp}\n")
    return "You are successfully signed in using google"
    

#creating fb routes 
@app.route("/fb-login")
def fb_login():
    facebook = requests_oauthlib.OAuth2Session(
        FB_CLIENT_ID, redirect_uri=URL + "/fb-callback", scope=FB_SCOPE
    )
    authorization_url, _ = facebook.authorization_url(FB_AUTHORIZATION_BASE_URL)

    return flask.redirect(authorization_url)


@app.route("/fb-callback")
def callback():
    facebook = requests_oauthlib.OAuth2Session(
        FB_CLIENT_ID, scope = FB_SCOPE, redirect_uri=URL + "/fb-callback"
    )

    # we need to apply a fix for Facebook here
    facebook = facebook_compliance_fix(facebook)

    facebook.fetch_token(
        FB_TOKEN_URL,
        client_secret=FB_CLIENT_SECRET,
        authorization_response=flask.request.url,
        #return "You are successfully signed in using facebook"
        
    )
    facebook_user_data = facebook.get(
        "https://graph.facebook.com/me?fields=id,name,email,picture{url}"
    ).json()

    email = facebook_user_data["email"]
    name = facebook_user_data["name"]
    picture_url = facebook_user_data.get("picture", {}).get("data", {}).get("url")

    return f"""
    User information: <br>
    Name: {name} <br>
    Email: {email} <br>
    Avatar <img src="{picture_url}"> <br>
    <a href="/">Home</a>
    """
    

if __name__ == '__main__':
    app.run(debug=True)