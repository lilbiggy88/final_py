from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user 
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class FormData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.String(10))
    text = db.Column(db.String(100))

db.create_all()




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Sign Up!")

def validate_username(self, username):
    existing_username = User.query.filter_by(username=username.data).first()

    if existing_username:
        raise ValidationError("This username is already in use! Please choose a different username.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login!")


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'] )
@login_required
def dashboard():

   data = FormData.query.all()
   return render_template('dashboard.html', data=data)

def get_time_options():
    times = []
    start_hour = 0
    end_hour = 23
    interval = 15

    for hour in range(start_hour, end_hour + 1):
        for minute in range(0, 60, interval):
            formatted_hour = str(hour).zfill(2)
            formatted_minute = str(minute).zfill(2)
            time = f'{formatted_hour}:{formatted_minute}'
            times.append(time)

    return times
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@app.route('/scheduler', methods=['GET', 'POST'])
@login_required
def scheduler():

    if request.method == 'POST':
        times = request.form.getlist('time[]')
        texts = request.form.getlist('text[]')

        # Store submitted data in the database
        for i in range(len(times)):
            form_data = FormData(time=times[i], text=texts[i])
            db.session.add(form_data)
        db.session.commit()

        return redirect('/dashboard')

    return render_template('scheduler.html', times=get_time_options())


if __name__ == '__main__':
    app.run(debug=True)