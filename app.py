from flask import Flask, render_template, request, url_for, flash, jsonify
from werkzeug.utils import redirect
from flask_mysqldb import MySQL
from my_secrets import MySecrets
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
      print("Unknown")
      flash("Unknown")
    elif result[0] == 1:
        print("Safe")
        flash("Safe")
    else:
      print("Malintent detected")
      flash("Malintent detected")

  return redirect(url_for("home"))

if __name__ == "__main__":
  app.run(debug=True)