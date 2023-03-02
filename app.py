from flask import Flask, render_template, request, url_for, flash
from werkzeug.utils import redirect
from flask_mysqldb import MySQL
from my_secrets import MySecrets

app = Flask(__name__)
app.secret_key = [MySecrets.key]

app.config['MYSQL_HOST'] = MySecrets.host
app.config['MYSQL_USER'] = MySecrets.user
app.config['MYSQL_PASSWORD'] = MySecrets.password
app.config['MYSQL_DB'] = MySecrets.db

mysql = MySQL(app)

@app.route("/")
def home():
  cursor = mysql.connection.cursor()
  cursor.execute("Select * FROM attack_data_tbl")
  data = cursor.fetchall()
  return render_template('index.html', attacks = data)