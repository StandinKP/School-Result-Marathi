from flask import Flask, render_template, redirect, make_response, json, url_for, flash, request, session, logging, jsonify
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from pymongo.errors import DuplicateKeyError
import os
from functools import wraps
from flask_cors import CORS
from random import randint
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import secrets
from PIL import Image
import pdfkit
import socket

config = pdfkit.configuration(wkhtmltopdf="C:\Program Files\wkhtmltopdf\\bin\wkhtmltopdf.exe")

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config.from_pyfile('config.cfg')



mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
CORS(app)
ip = socket.gethostbyname(socket.gethostname())

s = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))

# Check if user logged in
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Routes


@app.route("/")
def index():
    if 'logged_in' in session:
        teacher = mongo.db.users.find_one({"username": session['username']})
        students = mongo.db.students.find({"teacherId": teacher['teacherId']})
        students_count = mongo.db.students.count_documents({"teacherId": teacher['teacherId']})

    else:
        flash("Please login first", 'warning')
        return redirect(url_for('login'))
    return render_template('index.html', students=students, teacher=teacher, students_count=students_count)


@app.route("/register/", methods=['GET', 'POST'])
def register():
    if 'logged_in' in session:
        return redirect(url_for('index'))

    default_pic = url_for('static', filename='img/default.jpg')
    if request.method == 'POST':
        user = mongo.db.users.find_one({"username": request.form['username']})
        user1 = mongo.db.users.find_one({"email": request.form['email']})
        if user:
            flash("Username already taken", "danger")
            return redirect(url_for('register'))

        elif user1:
            flash("Email already taken", "danger")
            return redirect(url_for('register'))

        elif request.form['password'] == request.form['confirm_password']:
            hashed_password = bcrypt.generate_password_hash(
                request.form['password']).decode('utf-8')

            try:
                mongo.db.users.insert_one({
                    "teacherId": request.form['fname'][0:3]  + request.form['lname'][0:2] + str(randint(111, 999)),
                    "fname": request.form['fname'],
                    "lname": request.form['lname'],
                    "username": request.form['username'],
                    "school_name": request.form['school_name'],
                    "email": request.form['email'],
                    "password": hashed_password,
                    "profile_pic": default_pic,
                    "type": "teacher"
                })

                flash('Your account has been created! Please login!', 'success')

                return redirect(url_for('login'))

            except DuplicateKeyError:
                flash("User already exists!", 'success')
        elif request.form['password'] != request.form['confirm_password']:
            flash(
                "Please enter same password in confirm password and password fields!", 'danger')

    return render_template('register.html', title='Register')


@app.route("/login/", methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        user = mongo.db.users.find_one({"username": request.form['username']})

        if user and bcrypt.check_password_hash(user['password'], request.form['password']):
            session['logged_in'] = True
            session['username'] = request.form['username']
            
            session['profile_pic'] = user['profile_pic']
            session['teacherId'] = user['teacherId']
            next_page = request.args.get('next')

            return redirect(next_page) if next_page else redirect(url_for('index'))

            return redirect(url_for('login'))

        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html', title='Login')


@app.route("/logout/")
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(12)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/img', picture_fn)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return url_for('static', filename='img/' + picture_fn)


@app.route("/account/<username>/", methods=['GET', 'POST'])
def account(username):
    if 'logged_in' in session:
        old_user = mongo.db.users.find_one({"username": session['username']})

        if request.method == 'POST' and username == session['username']:
            picture = request.files['picture']
            email = request.form['email']
            fname = request.form['fname']
            lname = request.form['lname']

            if picture:
                profile_pic = save_picture(picture)

            else:
                profile_pic = session['profile_pic']

            mongo.db.users.update_one({"username": session['username']}, {"$set": {
                "fname": fname,
                "lname": lname,
                "profile_pic": profile_pic,
                "email": email
            }})

            new_user = mongo.db.users.find_one({"username": username})

            session['username'] = new_user['username']
            session['email'] = new_user['email']
            session['profile_pic'] = new_user['profile_pic']
            flash('Account updated!', 'success')

            return redirect(url_for("account", username=session["username"]))

        elif request.method == "GET":
            user = mongo.db.users.find_one({"username": username})
            session['username'] = user['username']
            session['email'] = user['email']
            session['profile_pic'] = user['profile_pic']

        new_user = mongo.db.users.find_one({"username": session['username']})
        profile_pic = new_user['profile_pic']

        return render_template('account.html', title='Account', profile_pic=profile_pic, user=user)
    user = mongo.db.users.find_one({"username": username})
    return render_template('account.html', title='Profile', user=user)



@app.route("/add_result", methods=['GET', 'POST'])
@login_required
def add_result():
    if request.method == "POST":
        teacher = mongo.db.users.find_one({"username": session['username']})
        mongo.db.students.insert_one({
            "studentId": str(randint(11111111, 99999999)),
            "name": request.form['name'],
            "standard": request.form['standard'],
            "teacherId": teacher['teacherId'], 
            "progress": request.form['progress'], 
            "talents": request.form['talents'], 
            "improvements": request.form['improvements'], 
            "grade": 
                {'marathi': request.form['marathi'],
                'hindi': request.form['hindi'],
                'english': request.form['english'],
                'maths': request.form['maths'],
                's_science': request.form['s_science'],
                'sociology': request.form['sociology'],
                'art': request.form['art'],
                'work_experience': request.form['work_experience'],
                'physical_edu': request.form['physical_edu']}
            })

        flash("New result added", 'success')
        return redirect(url_for('index'))

    return render_template('add_result.html', title='New Result')


@app.route('/view_result/<studentId>')
def view_result(studentId):
    student = mongo.db.students.find_one({"studentId": studentId})
    teacher = mongo.db.users.find_one({"teacherId": student['teacherId']})

    return render_template('view_result.html', title='View Result', student=student, teacher=teacher)

@app.route('/edit_result/<studentId>/', methods=['GET', 'POST'])
@login_required
def edit_result(studentId):
    student = mongo.db.students.find_one({"studentId": studentId})
    if request.method == "POST":
        name = request.form['name']
        mongo.db.students.update_one({ "studentId": studentId }, {
            '$set': {"name": name,
                    "progress": request.form['progress'], 
                    "talents": request.form['talents'], 
                    "improvements": request.form['improvements'],
                    "grade": 
                        {'marathi': request.form['marathi'],
                        'hindi': request.form['hindi'],
                        'english': request.form['english'],
                        'maths': request.form['maths'],
                        's_science': request.form['s_science'],
                        'sociology': request.form['sociology'],
                        'art': request.form['art'],
                        'work_experience': request.form['work_experience'],
                        'physical_edu': request.form['physical_edu']}
                    }})
        flash("Result updated", 'success')
        return redirect(url_for('view_result', studentId=studentId))
    return render_template('edit_result.html', student=student)


@app.route('/download_result/<studentId>/', methods=['GET', 'POST'])
@login_required
def download_result(studentId):
    student = mongo.db.students.find_one({"studentId": studentId})
    teacher = mongo.db.users.find_one({"username": session['username']})

    rendered = render_template('download_result.html', student=student, teacher=teacher)
    css = ['static/css/main.css']
    path = os.path.abspath(basedir+'/static/result/'+session['teacherId'])

    pdf = pdfkit.from_string(rendered, False, css=css, configuration=config)
    
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = "attachment; filename=" + student['studentId'] + ".pdf"

    return response

    
@app.route('/download_all/', methods=['GET', 'POST'])
def download_all():
    students = mongo.db.students.find({"teacherId": session['teacherId'] }) 
    teacher = mongo.db.users.find_one({"username": session['username']})


    css = ['static/css/main.css']
    rendered = render_template('result.html', ip=ip, students=students, teacher=teacher)
    pdf = pdfkit.from_string(rendered, False, css=css,  configuration=config)

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = "attachment; filename=" + teacher['teacherId'] + ".pdf"


    return response

@app.route('/forgot_password/', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        token = s.dumps(email, salt='change-password')

        msg = Message("Change password", recipients=[email])
        link = url_for('change_password', token=token, _external=True)
        msg.html = '''<h1>Change your password!</h1>
                   <a href=" '''+ link + ''' "><button class="btn btn-primary">Change password</button></a>'''
        mail.send(msg)
        flash('Link to change password has been sent to your email. Please check your email', 'info')
        return redirect(url_for("login"))

    return render_template('forgot_password.html')

@app.route('/change_password/<token>', methods=['GET', 'POST'])
def change_password(token):
    if request.method == 'POST':
        try:
            email = s.loads(token, salt='change-password', max_age=900)
            if request.form['password'] == request.form['confirm_password']:
                hash_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
                mongo.db.users.update_one({'email': email}, {'$set': {'password': hash_password}})
                flash("Your password has been changed. You can login now!", 'success')
                return redirect(url_for("login"))
            else:
                flash("Wrong password entered in both fields!", 'danger')

        except SignatureExpired or BadTimeSignature:
            flash('Your password couldn\'t be changed. Please try again!', 'danger')
            return redirect(url_for('change_password', token=token))

    return render_template('change_password.html', title='Change Password')

if __name__ == '__main__':
    app.run(debug=True,port=80,host='0.0.0.0')