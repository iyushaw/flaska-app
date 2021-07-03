import bcrypt
from flask import Flask,render_template, redirect
from flask.helpers import url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'sasasa'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(40), nullable=False)
    last_name = db.Column(db.String(40), nullable=False)
    username = db.Column(db.String(40), nullable=False, unique=True)
    password = db.Column(db.String(140), nullable=False)


class RegistrationForm(FlaskForm):
    first_name = StringField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "First Name"})
    last_name = StringField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Last Name"})
    username = StringField(validators=[InputRequired(), Length(min=6)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=4), EqualTo(password)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_name = User.query.filter_by(username=username.data).first()
        if existing_user_name:
            raise ValidationError("Username already exits!")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=6)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")




@app.route('/')
def index():
    title = "Home"

    return render_template('index.html', title=title)

@app.route('/login', methods=["GET", "POST"])
def login():
    title = "Login"

    form = LoginForm()

    return render_template('login.html', title=title, form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    title = "Register"

    form=RegistrationForm()

    if form.validate_on_submit():
        hashed__password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(first_name=form.first_name.data, 
                        last_name=form.last_name.data, 
                        username=form.username.data, 
                        password=hashed__password
                        )

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))


    return render_template('register.html', title=title,  form=form)

@app.route('/profile')
def profile():
    title = "Profile"

    return render_template('profile.html', title=title)

if __name__ == "__main__":
    app.run(debug=True)