from flask import Flask, render_template, request, url_for, flash, jsonify, session, Markup
from werkzeug.utils import redirect
from flask_mysqldb import MySQL
from my_secrets import MySecrets
import MySQLdb.cursors
import re
import pickle

app = Flask(__name__)
app.secret_key = [MySecrets.key]
model = pickle.load(open('model/cyber_model.pkl', 'rb'))
phish_model = pickle.load(open('model/phish_model.pkl', 'rb'))

app.config['MYSQL_HOST'] = MySecrets.host
app.config['MYSQL_USER'] = MySecrets.user
app.config['MYSQL_PASSWORD'] = MySecrets.password
app.config['MYSQL_DB'] = MySecrets.db

mysql = MySQL(app)



@app.route('/graphs')
def graphs():
  return render_template('graphs.html')

@app.route("/")
def home():
  cursor = mysql.connection.cursor()
  cursor.execute("Select * FROM attack_all")
  data = cursor.fetchall()
  return render_template('index.html', attacks = data)

@app.route('/api')
def api():
  cursor = mysql.connection.cursor()
  cursor.execute("Select * FROM attack_all")
  data = cursor.fetchall()
  return jsonify(data)

@app.route("/insert", methods=['POST'])
def insert():
  if request.method == 'POST':
    flash("Data Inserted Successfully")
    #Form Fields
    victim = request.form['victim']
    location = request.form['location']
    industry = request.form['industry']
    attacker_location = request.form['attacker_location']
    malware = request.form['malware']
    motive = request.form['motive']
    attack_type = request.form['attack_type']
    sub_attack_type = request.form['sub_attack_type']
    date_of_attack = request.form['date_of_attack']

    cursor = mysql.connection.cursor()
    cursor.execute("""INSERT INTO attack_all (victim, location, industry, attacker_location, malware, motive, attack_type, sub_attack_type, date_of_attack) 
    VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
    (victim, location, industry, attacker_location, malware, motive, attack_type, sub_attack_type, date_of_attack))
    mysql.connection.commit()
    return redirect(url_for("home"))

def updateSecurityStatus(email, token):
   cursor = mysql.connection.cursor()
   sql = "UPDATE accounts SET status=1, token=%s WHERE email=%s"
   #val = (email)
   cursor.execute(sql,(token, email))
   mysql.connection.commit()

@app.route('/delete/<string:id_data>', methods = ['GET'])
def delete(id_data):
  cursor = mysql.connection.cursor()
  cursor.execute("DELETE FROM attack_all WHERE id=%s", (id_data,))
  mysql.connection.commit()
  flash("Record deleted Successfully")
  return redirect(url_for('home'))  

@app.route('/predict', methods=['POST'])
def predict():
  if request.method == 'POST':
    motive = request.form['motive']
    print(motive)
    actor_location = request.form['actor_location']
    actor = request.form['actor']
    victim = request.form['victim']

    result = model.predict([[motive, actor_location, actor, victim, 1, -1, 1, 1, 0]])
    print(result[0])

    if result[0] == 0:
      print("Mixed")
      flash("Mixed")
    elif result[0] == 1:
        print("Exploitative")
        flash("Exploitative")
    else:
      print("Disruptive")
      flash("Disruptive")

  return redirect(url_for("home"))

@app.route('/predictPhish', methods=['POST'])
def predictPhish():
  if request.method == 'POST':
    sfh = request.form['sfh']
    popUPWindow = request.form['popUPWindow']
    SSL_final_state = request.form['SSL_final_state']
    Request_url = request.form['Request_url']
    url_of_anchor = request.form['url_of_anchor']
    web_traffic = request.form['web_traffic']
    url_length = request.form['url_length']
    age_of_domain = request.form['age_of_domain']
    having_ip = request.form['having_ip']

    result = phish_model.predict([[sfh, popUPWindow, SSL_final_state, Request_url, url_of_anchor, web_traffic, url_length, age_of_domain, having_ip]])
    print(result[0])

    if result[0] == 0:
      print("Sorry we can't conclusively predict your attack type We need more info")
      flash("Sorry we can't conclusively predict your attack type We need more info")
    elif result[0] == 1:
        print("Everything looks good based on the indicators you provided")
        flash("Everything looks good based on the indicators you provided")
    else:
      print("Your indicators show this is a Social Engineering attack you can add it to our database as disruptive")
      flash("Your indicators show this is a Social Engineering attack you can add it to our database as disruptive")

  return redirect(url_for("home"))

# http://localhost:5000/pythonlogin/ - this will be the login page, we need to use both GET and POST requests
@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
# Output message if something goes wrong...
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password))
        # Fetch one record and return result
        account = cursor.fetchone()
                # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['email'] = account['email']

            if account['status'] == 1 and account['role'] != 0:
               flash(Markup('Account Suspended for suspicious activities, <a href="../auth/login_auth">contact admin</a>'), "danger")
               return redirect(url_for('login'))
            elif account['role'] == 0:
               return redirect(url_for('admin_user'))
            else:
               return redirect(url_for('home_user'))
        else:
            # Account doesnt exist or username/password incorrect
            flash("Incorrect username/password!", "danger")
    return render_template('auth/login.html',title="Login")

@app.route('/auth/login', methods=['GET', 'POST'])
def log_in_auth():
# Output message if something goes wrong...
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'token' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        token = request.form['token']
    
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s AND token = %s', (username, password, token))
        # Fetch one record and return result
        account = cursor.fetchone()
                # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['email'] = account['email']

            if account['status'] == 1:
               downGradeSecurityStatus(email=account['email'])
            else:
               return redirect(url_for('home_user'))
        else:
            # Account doesnt exist or username/password incorrect
            flash("Incorrect username/password!", "danger")
    return render_template('auth/login.html',title="Login")

def downGradeSecurityStatus(email):
   cursor = mysql.connection.cursor()
   sql = "UPDATE accounts SET status=0 WHERE email='%s'" %email
   cursor.execute(sql)
   mysql.connection.commit()

   flash("Threat level averted", "success")
   return redirect(url_for('login'))
# http://localhost:5000/pythinlogin/register 
# This will be the registration page, we need to use both GET and POST requests
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
                # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # cursor.execute('SELECT * FROM accounts WHERE username = %s', (username))
        cursor.execute( "SELECT * FROM accounts WHERE username LIKE %s", [username] )
        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            flash("Account already exists!", "danger")
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash("Invalid email address!", "danger")
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash("Username must contain only characters and numbers!", "danger")
        elif not username or not password or not email:
            flash("Incorrect username/password!", "danger")
        else:
        # Account doesnt exists and the form data is valid, now insert new account into accounts table
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (email, username, password))
            mysql.connection.commit()
            flash("You have successfully registered!", "success")
            return redirect(url_for('login'))

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        flash("Please fill out the form!", "danger")
    # Show registration form with message (if any)
    return render_template('auth/register.html',title="Register")

# http://localhost:5000/pythinlogin/home 
# This will be the home page, only accessible for loggedin users

@app.route('/auth/login_auth')
def auth_login():
   return render_template('auth/login_auth.html')

@app.route('/pythonlogin/admin_user')
def admin_user():
   if 'loggedin' in session:
      cursor = mysql.connection.cursor()
      cursor.execute("SELECT * FROM accounts")
      data = cursor.fetchall()
      return render_template('home/admin_home.html', username=session['username'], title="Admin Home", users=data)
   
   return redirect(url_for('login'))

@app.route('/pythonlogin/home_user')
def home_user():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home/home.html', username=session['username'],title="Home")
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))    


@app.route('/pythonlogin/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('auth/profile.html', email=session['email'], username=session['username'],title="Profile")
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))  

@app.route('/phish', methods=['POST'])
def phish():
    #flash("Still working on this", "success")
    if 'loggedin' in session:
        url = request.form['url']
        url_pattern = "^http:\/\/"
        ssl = re.match(url_pattern, url)
        anchor = re.findall("@", url)
        having_ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', url)
        ssl_value = 0
        length_value = 0
        anchor_value = 0
        having_ip_value = 0
        sfh = 0
        popUPWindow = 0
        Request_url = 0
        web_traffic = 0
        age_of_domain = 0

        if ssl:
            ssl_value = 1
        else:
            ssl_value = -1
        
        if len(url) < 20:
            length_value = 1
        else:
            length_value = -1
        
        if anchor:
            anchor_value = 1
        else:
            anchor_value = -1
        
        if having_ip:
            having_ip_value = 1
        else:
            having_ip_value = -1

        
        result = phish_model.predict([[sfh, popUPWindow, ssl_value, Request_url, anchor_value, web_traffic, length_value, age_of_domain, having_ip_value]])
        print(result[0])

        if result[0] == 0:
          print("Sorry we can't conclusively predict your attack type We need more info")
          flash("Sorry we can't conclusively predict your attack type We need more info")
        elif result[0] == 1:
            print("Everything looks good based on the indicators you provided")
            flash("Everything looks good based on the indicators you provided")
        else:
          print("Your indicators show this is a Social Engineering attack you can add it to our database as disruptive")
          flash("Your indicators show this is a Social Engineering attack you can add it to our database as disruptive", "danger")
          
          import random
          import math

          digits = [i for i in range(0, 10)]
          token = ""
          
          for i in range(6):
             index = math.floor(random.random() * 10)
             token += str(digits[index])

          print(token)
          updateSecurityStatus(session['email'], token)
          return render_template('auth/login.html', title="Login")

    return render_template('home/home.html', username=session['username'],title="Home")
 

if __name__ == "__main__":
  app.run(debug=True)