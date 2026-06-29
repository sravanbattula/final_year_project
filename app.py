import mysql.connector

from flask import Flask, render_template, request, redirect, url_for, session, flash

import numpy as np

app = Flask(__name__)

app.secret_key = 'sfarshthstjjejyrkjyr'

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    port="3306",
    database='malware'
)


mycursor = mydb.cursor()

def executionquery(query, values):
    mycursor.execute(query, values)
    mydb.commit()

def retrivequery1(query, values):
    mycursor.execute(query, values)
    data = mycursor.fetchall()
    return data

def retrivequery2(query):
    mycursor.execute(query)
    data = mycursor.fetchall()
    return data

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if any field is empty
        if not email or not password or not confirm_password:
            flash("All fields are required.", "danger")
            return render_template('register.html')

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return render_template('register.html')

        # Check if email already exists
        query = "SELECT UPPER(email) FROM users"
        email_data = retrivequery2(query)
        email_data_list = [i[0] for i in email_data]
        
        if email.upper() in email_data_list:
            flash("This email ID already exists!", "danger")
            return render_template('register.html')

        # Insert new user into the database
        query = "INSERT INTO users (name, email, password) VALUES (%s ,%s, %s)"
        values = ( name ,email, password)
        executionquery(query, values)

        flash("Successfully registered! Please log in.", "success")
        return redirect(url_for('login')) 

    return render_template('register.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        query = "SELECT UPPER(email) FROM users"
        email_data = retrivequery2(query)
        email_data_list = [i[0] for i in email_data]

        if email.upper() in email_data_list:
            query = "SELECT password FROM users WHERE email = %s"
            values = (email,)
            password_data = retrivequery1(query, values)
            
            if password == password_data[0][0]:
                # Set session for the user
                session['user_email'] = email
                return redirect(url_for('user_home'))  
            else:
                flash("Invalid Password!", "danger")
        else:
            flash("This email ID does not exist!", "danger")
        
        return render_template('login.html')
    
    return render_template('login.html')

@app.route('/user_home')
def user_home():
    if 'user_email' not in session:
        flash("You must be logged in to access this page.", "warning")
        return redirect(url_for('login'))  
    
    return render_template('user_home.html')

import pickle

# Load the trained XGBoost model
with open("XGBoost_model.pkl", "rb") as file:
    model = pickle.load(file)

# Feature names in order
feature_names = [
    'SectionsMaxEntropy', 'Subsystem', 'DllCharacteristics', 'MajorSubsystemVersion',
    'SizeOfOptionalHeader', 'ResourcesMinEntropy', 'SectionsMeanEntropy', 'ResourcesMaxEntropy',
    'Characteristics', 'CheckSum', 'SectionsNb', 'MinorLinkerVersion',
    'ExportNb', 'VersionInformationSize', 'SectionsMinEntropy'
]

@app.route("/prediction", methods=["GET", "POST"])
def prediction():
    if request.method == "POST":
        try:
            # Extract input features based on names
            features = [float(request.form[name]) for name in feature_names]
            features = np.array(features).reshape(1, -1)

            # Predict using the loaded model
            prediction = model.predict(features)[0]
            result = "Malware file (malicious)" if prediction == 1 else "Legitimate file (benign)"

            return render_template("prediction.html", result=result)

        except Exception as e:
            return render_template("prediction.html", result=f"Error: {str(e)}")

    return render_template("prediction.html", feature_names=feature_names)


if __name__ == "__main__":
    app.run(debug=True)