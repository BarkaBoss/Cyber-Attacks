from flask import Flask, render_template, request, url_for, flash, jsonify
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
    location = request.form['locaton']
    industry = request.form['industry']
    attacker_location = request.form['attacker_location']
    malware = request.form['malware']
    motive = request.form['motive']
    attack_type = request.form['attack_type']
    sub_attack_type = request.form['sub_attack_type']
    date_of_attack = request.form['date_of_attack']

    cursor = mysql.connection.cursor()
    cursor.execute("""INSERT INTO attacks_all (victim, location, industry, attacker_location, malware, motive, attack_type, sub_attack_type, date_of_attack) 
    VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
    (victim, location, industry, attacker_location, malware, motive, attack_type, sub_attack_type, date_of_attack))
    mysql.connection.commit()
    return redirect(url_for("home"))

@app.route('/delete/<string:id_data>', methods = ['GET'])
def delete(id_data):
  flash("Record deleted Successfully")
  cursor = mysql.connection.cursor()
  cursor.execute("DELETE FROM attacks_all WHERE id=%s", (id_data,))
  mysql.connection.commit()
  return redirect(url_for('Home'))  

if __name__ == "__main__":
  app.run(debug=True)