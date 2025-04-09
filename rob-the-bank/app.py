from flask import Flask, redirect, render_template, request, url_for, flash, get_flashed_messages
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, login_required, logout_user
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY']="supersecretkey"

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///ctf.db"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Roles(db.Model):
    id=db.Column(db.Integer(), primary_key=True)
    rolename = db.Column(db.String(length=30), nullable=False, unique=True)
    users=db.relationship("Users", secondary="user_role", back_populates="roles")

class Users(db.Model, UserMixin):
    id=db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    password = db.Column(db.String(length=255), nullable=False)
    nickname = db.Column(db.String(length=30), nullable=False)

    roles=db.relationship("Roles", secondary="user_role", back_populates="users")

    def has_role(self, role):
        return bool(
            Roles.query
            .join(Roles.users)
            .filter(Users.id==self.id)
            .filter(Roles.rolename==role)
            .count()==1
        )

class UserRole(db.Model):
    __tablename__="user_role"
    user_id=db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    role_id=db.Column(db.Integer, db.ForeignKey("roles.id"), primary_key=True)

with app.app_context():
    db.create_all()

    if not Roles.query.filter_by(rolename="ADMIN").first():
        role1 = Roles(rolename="ADMIN")
        db.session.add(role1)
        db.session.commit()
    if not Roles.query.filter_by(rolename="USER").first():
        role2 = Roles(rolename="USER")
        db.session.add(role2)
        db.session.commit()
    if not Users.query.filter_by(username="bank_admin").first():
        hashed_password = generate_password_hash("GREATHACKER01", method='pbkdf2:sha256')
        myuser=Users(username="bank_admin", password=hashed_password, nickname="Admin")
        myuser.roles.append(role1)
        db.session.add(myuser)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        username = request.form.get('username').lower()
        password = request.form.get('password')
        nickname = request.form.get('nickname')
        username=username.lower()
        existing_user = Users.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Choose another one.", "danger")
            return redirect(url_for('register'))
 
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = Users(username=username, password=hashed_password, nickname=nickname)
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
 
    return render_template('register.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form.get('username').lower()
        password = request.form.get('password')

        user = Users.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return render_template("Dashboard.html", nickname=current_user.nickname)
        else:
            flash("Invalid username or password", "danger")
            return render_template('login.html')
    
    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    return render_template('Dashboard.html', username=current_user.username)

@app.route("/assign", methods=["GET", "POST"])
@login_required
def assignrole():
    if request.method == 'POST':
        username = request.form.get('username').lower()
        rolename = request.form.get('rolename').upper()

        user = Users.query.filter_by(username=username).first()
        role = Roles.query.filter_by(rolename=rolename).first()

        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('dashboard'))
        if not role:
            flash("Role not found.", "danger")
            return redirect(url_for('dashboard'))

        if role in user.roles:
            flash("User already has this role.", "warning")
        else:
            user.roles.append(role)
            db.session.commit()
            flash(f"Role '{rolename}' assigned to user '{username}'.", "success")

        return redirect(url_for('dashboard'))

    return render_template('dashboard.html')
    
def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.has_role(role):
                flash("You do not have the required permissions to access this page.", "danger")
                return redirect(url_for('dashboard'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/withdraw', methods=["POST", "GET"])
@role_required('ADMIN')
def withdraw():
    if current_user.username=='bank_admin':
        amount="CTF{$1 Billion_is_transferred_to_Tommy}"
        message="Congratulations!! on Successful Hacking of secret informations, bypassing strict authentication, using vulnerable authorization kept by the owners of this website for cost cutting!"
    else:
        amount="You don't have any salary/account with the bank!"
        message=""

    return render_template("withdraw.html", amount=amount, message=message)

@app.route('/user')
@role_required('ADMIN')
def user():
    return render_template("getusers.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("3000"))