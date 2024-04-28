from flask import Flask, render_template, request,redirect, url_for,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import pickle
import numpy as np

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = 'secret_key'
db = SQLAlchemy(app)

class User(db.Model):
    __bind_key__ = None  # Use the primary database
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
with app.app_context():
    # db.drop_all()  # Drop all tables
    db.create_all()

@app.route('/')
def login():
    return render_template('Login.html')

@app.route('/Login', methods=['POST','GET'])
def Login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user is None:
            alert_script = '<script>alert("Your email is not registered."); window.history.back();</script>'
            return alert_script
        if user and user.check_password(password):
            session['email'] = user.email
            return redirect(url_for('index'))
        else:
            alert_script = f'<script>alert("Incorrect password. Please try again."); window.location.href = "{url_for("login")}";</script>'
            return alert_script

@app.route('/register',methods=['GET','POST'])
def register():
        # handle request
    name = request.form['Firstname']
    email = request.form['email']
    password = request.form['password']
    registercode = request.form['regcode']
    if registercode == '1975':
        try:
            new_user = User(name=name, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
                # Redirect to the 'man' page after successful registration
            return redirect(url_for('login'))

        except Exception as e:
            # If an error occurs, rollback the session and display an alert
            db.session.rollback()
            error_message = f"An error occurred: {str(e)}. Please try again."
            return f"""<script>
                    alert('{error_message}');
                    window.history.back();
                </script>"""
    else:
        alert_script = f'<script>alert("NO! NO! NO! do not try to register without permission of your SIR!!! "); window.location.href = "{url_for("login")}";</script>'
        return alert_script
    
@app.route('/Admin_Login')
def Adminlogin():
    return render_template('admin.html')

@app.route('/AdminLogin', methods=['POST','GET'])
def AdminLogin():
    email = request.form['email']
    password = request.form['password']
    # Example of validating the email and password 
    if email == 'pasinduranasinghe186@gmail.com' and password == '1995456':
        # If email and password are correct, redirect to the home page
        return redirect(url_for('admin'))
    else:
        alert_script = f'<script>alert("Incorrect credentials try again!!"); window.location.href = "{url_for("Adminlogin")}";</script>'
        return alert_script
    
@app.route('/AdminDashboard')
def admin():
    if session['email']:
        all_users = User.query.all()
        return render_template('AdminDashboard.html', all_users=all_users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # Fetch the user by ID
    user_to_delete = User.query.get_or_404(user_id)
    
    # Delete the user from the database
    db.session.delete(user_to_delete)
    db.session.commit()
    
    # Redirect back to the dashboard or Admin.html page
    return redirect(url_for('admin'))


@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/grade6')
def grade6():
    return render_template('grade_6.html')

@app.route('/grade7')
def grade7():
    return render_template('grade_7.html')

if __name__ == "__main__":
    app.run(debug=True)