from flask import Flask, render_template, redirect, request, session, flash
import sqlite3
from flask_bcrypt import Bcrypt
import datetime

DATABASE = "database.db"  # file path to the database
app = Flask(__name__)
bcrypt = Bcrypt(app)  # initialising bcrypt
app.secret_key = "w3wkjdxdckiu-p[0;iliketoeatdogsandcats4[7uyhxnhjdcvgf"  # key used to secure session data


def connect(db_file):  # creates a connection with the database
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except sqlite3.Error as e:
        print(e)
    return None

@app.context_processor
def login_context_processor():  # jinja context processor to check if you are logged in
    return dict(logged_in=logged_in)  # calls the logged_in function to jinja


def logged_in():  # checks whether you are logged in
    if session.get("email"):  # if email exists in session tuple
        return True
    else:
        return False


@app.context_processor
def admin_context_processor():
    return dict(is_admin=is_admin)


def is_admin():
    if logged_in() and session.get("type") == 1:
        return True
    else:
        return False


@app.route('/')
def render_home():
    return render_template('home.html')


@app.route('/database')
def render_database():
    con = connect(DATABASE)
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id"
    cur = con.cursor()
    cur.execute(query)
    entry_list = cur.fetchall()  # fetch all the rows which matches the query
    query = "SELECT id, name FROM categories"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return render_template('database.html', entries=entry_list, categories=category_list)


@app.route('/database/<category_id>')
def render_database_categories(category_id):
    con = connect(DATABASE)
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id " \
            "WHERE category_id=?"
    cur = con.cursor()
    cur.execute(query, (category_id,))
    entry_list = cur.fetchall()
    query = "SELECT id, name " \
            "FROM categories"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return render_template('database.html', entries=entry_list, categories=category_list)


@app.route('/search_type_mythicals', methods=['GET', 'Post'])
def render_search_type_mythicals():
    search = request.form['type_search']
    query = "(Type LIKE ? or Second_Type LIKE ?)"
    search = "%" + search + "%"
    con = connect(DATABASE)
    cur = con.cursor()
    cur.execute(query, (search, search))
    tag_list = cur.fetchall()
    con.close()
    if len(tag_list) == 0:
        return redirect("/no_results")
    else:
        return render_template("mythicals.html", tags=tag_list)


@app.route('/login', methods=["POST", "GET"])
def render_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"].strip()
        con = connect(DATABASE)
        query = """SELECT id, password, f_name, l_name, type 
        FROM users 
        WHERE email = ?"""
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()
        try:
            user_id = user_data[0]
            f_name = user_data[2]
            l_name = user_data[3]
            hashed_password = user_data[1]
        except:
            return redirect("/login?error=Email+invalid+or+password+incorrect")
        if not bcrypt.check_password_hash(hashed_password, password):
            return redirect("/login?error=Email+invalid+or+password+incorrect")
        session['email'] = email
        session['user_id'] = user_id
        session['f_name'] = f_name
        session['l_name'] = l_name
        session['type'] = user_data[4]

        print(session)
        return redirect("/")
    return render_template('login.html')


@app.route('/logout')
def logout():
    for key in list(session.keys()):  # empties the session
        session.pop(key)
    flash('You have successfully logged out.')
    return redirect("/login")


@app.route('/signup', methods=["POST", "GET"])
def render_signup_page():
    if request.method == "POST":
        success = True
        print(request.form)
        f_name = request.form.get("f_name").title().strip()
        l_name = request.form.get("l_name").title().strip()
        email = request.form.get("email").lower().strip()
        password = request.form.get("password")
        password2 = request.form.get("password2")
        teacher = request.form.get("type")
        if teacher == 'on':
            account_type = 1
        else:
            account_type = 0
        if password != password2:
            flash("Passwords do not match")
            success = False
        if len(password) < 8:
            flash("Password must be at least 8 characters")
            success = False
        hashed_password = bcrypt.generate_password_hash(password)
        con = connect(DATABASE)
        query = "INSERT INTO users (f_name, l_name, email, password, type) VALUES (?, ?, ?, ?, ?)"
        cur = con.cursor()
        try:
            cur.execute(query, (f_name, l_name, email, hashed_password, account_type))
        except sqlite3.IntegrityError:
            con.close()
            flash("Email is already used")
            success = False
        if success:
            con.commit()
            con.close()
            return redirect("/login")
        else:
            con.close()
            return redirect("/signup")
    return render_template('signup.html')


@app.route('/entry/<entry_id>')
def render_entry(entry_id):
    con = connect(DATABASE)
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name, entries.image, users.f_name, users.l_name, entries.date " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id " \
            "INNER JOIN users ON entries.user_id=users.id " \
            "WHERE entries.id=?"
    cur = con.cursor()
    cur.execute(query, (entry_id,))
    entry_info = cur.fetchone()
    con.close()
    print(entry_info)
    return render_template('entry.html', entry=entry_info)


@app.route('/admin', methods=["POST", "GET"])
def render_admin_page():
    if not is_admin():
        flash("You must be an admin")
        return redirect("/")
    con = connect(DATABASE)
    query = "SELECT id, name FROM categories"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    if request.method == "POST":
        success = True
        print(request.form)
        maori = request.form.get("maori").lower().strip()
        english = request.form.get("english").lower().strip()
        definition = request.form.get("definition").capitalize().strip()
        level = request.form.get("level")
        category_id = request.form.get("password2")
        user_id = session.get("user_id")
        con = connect(DATABASE)
        query = "INSERT INTO entries (maori, english, definition, level, category_id, user_id) VALUES (?, ?, ?, ?, ?, ?)"
        cur = con.cursor()
        try:
            cur.execute(query, (maori, english, definition, level, category_id, user_id))
        except sqlite3.IntegrityError:
            con.close()
            flash("Failed to add new entry. Please check that the data you've entered meets the requirements.")
            success = False
        if success:
            con.commit()
            con.close()
            return redirect("/database")
        else:
            con.close()
            return redirect("/admin")
    return render_template('admin.html', categories=category_list)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
