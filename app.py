from flask import Flask, render_template, redirect, request, session, flash
import sqlite3
from flask_bcrypt import Bcrypt
import datetime

# E:/Min/School Work/DTS/Te-Reo-Dictionary/database.db
DATABASE = "E:/Min/School Work/DTS/Te-Reo-Dictionary/database.db"  # file path to the database
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


@app.route('/no_results')
def render_no_results():
    return render_template('no_results.html')


@app.route('/database/<category_id>')
def render_database_categories(category_id):
    con = connect(DATABASE)
    cur = con.cursor()
    if category_id == '-1':
        query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name " \
                "FROM entries " \
                "INNER JOIN categories ON entries.category_id=categories.id " \
                "ORDER BY entries.date DESC "

        cur.execute(query)
    else:
        query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name " \
                "FROM entries " \
                "INNER JOIN categories ON entries.category_id=categories.id " \
                "WHERE category_id=? "\
                "ORDER BY entries.date DESC "
        cur.execute(query, (category_id, ))
    entry_list = cur.fetchall()
    query = "SELECT id, name " \
            "FROM categories " \
            "ORDER BY date ASC "
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    if len(entry_list) == 0:
        return redirect("/no_results")
    else:
        return render_template('database.html', entries=entry_list, categories=category_list, id=int(category_id))


@app.route('/search', methods=['GET', 'Post'])
def render_search():
    search = "%" + request.form['search'] + "%"
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id " \
            "WHERE (entries.maori LIKE ? or entries.english LIKE ? or entries.level LIKE ?) " \
            "ORDER BY entries.date DESC "
    con = connect(DATABASE)
    cur = con.cursor()
    cur.execute(query, (search, search, search))
    entry_list = cur.fetchall()
    query = "SELECT id, name " \
            "FROM categories " \
            "ORDER BY date ASC "
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    if len(entry_list) == 0:
        return redirect("/no_results")
    else:
        return render_template("database.html", entries=entry_list, categories=category_list, id=-1)


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


@app.route('/login', methods=["POST", "GET"])
def render_login():
    if logged_in():
        return redirect("/")
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"].strip()
        con = connect(DATABASE)
        cur = con.cursor()
        query = "SELECT id, password, f_name, l_name, type " \
                "FROM users " \
                "WHERE email = ?"
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()
        try:
            user_id = user_data[0]
            f_name = user_data[2]
            l_name = user_data[3]
            hashed_password = user_data[1]
        except TypeError:
            flash('An account with this email does not exist.')
            return redirect("/login")
        if not bcrypt.check_password_hash(hashed_password, password):
            flash('Your password is incorrect.')
            return redirect("/login")
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
    if logged_in():
        return redirect("/")
    if request.method == "POST":
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
            flash("Passwords do not match.")
            return redirect("/signup")
        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return redirect("/signup")
        hashed_password = bcrypt.generate_password_hash(password)
        con = connect(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO users (f_name, l_name, email, password, type) VALUES (?, ?, ?, ?, ?)"
        try:
            cur.execute(query, (f_name, l_name, email, hashed_password, account_type))
        except sqlite3.IntegrityError:
            con.close()
            flash("This email has already been used.")
            return redirect("/signup")
        con.commit()
        con.close()
        return redirect("/login")
    return render_template('signup.html')


@app.route('/admin', methods=["POST", "GET"])
def render_admin_page():
    if not is_admin():
        return redirect("/")
    con = connect(DATABASE)
    cur = con.cursor()
    query = "SELECT id, name FROM categories ORDER BY date ASC"
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return render_template('admin.html', categories=category_list)


@app.route('/add_entry', methods=["POST", "GET"])
def add_entry():
    if not is_admin():
        return redirect("/")
    else:
        if request.method == "POST":
            print(request.form)
            maori = request.form.get("maori").lower().strip()
            english = request.form.get("english").lower().strip()
            definition = request.form.get("definition").capitalize().strip()
            if definition == '':
                definition = 'Pending'
            level = request.form.get("level")
            category_id = request.form.get("category")
            user_id = session.get("user_id")
            con = connect(DATABASE)
            cur = con.cursor()
            query = "INSERT INTO entries (maori, english, definition, level, category_id, user_id) VALUES (?, ?, ?, ?, ?, ?)"
            try:
                cur.execute(query, (maori, english, definition, int(level), int(category_id), int(user_id)))
            except sqlite3.IntegrityError:
                con.close()
                flash("Failed to add entry. Please check you have met all the requirements.")
                return redirect("/admin")
            con.commit()
            con.close()
            flash("Your entry has been added.")
            return redirect("/")


@app.route('/add_category', methods=["POST", "GET"])
def add_category():
    if not is_admin():
        return redirect("/")
    if request.method == "POST":
        print(request.form)
        name = request.form.get("cat_name").lower().strip()
        user_id = session.get("user_id")
        con = connect(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO categories (name, user_id) VALUES (?, ?)"
        try:
            cur.execute(query, (name, int(user_id)))
        except sqlite3.IntegrityError:
            con.close()
            flash("A category with this name already exists.")
            return redirect("/admin")
        con.commit()
        con.close()
        flash("Your category has been added.")
        return redirect("/")


@app.route('/confirm_delete_entry/<entry_id>')
def render_confirm_delete_entry_page(entry_id):
    if not is_admin():
        return redirect("/")
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
    return render_template('confirm_delete_entry.html', entry=entry_info)


@app.route('/confirm_delete_category/', methods=["POST", "GET"])
def render_confirm_delete_category_page():
    if not is_admin():
        return redirect("/")
    if request.method == "POST":
        print(request.form)
        category_id = request.form.get("cat_id")
    con = connect(DATABASE)
    query = "SELECT categories.id, categories.name, users.f_name, users.l_name, categories.date " \
            "FROM categories " \
            "INNER JOIN users ON categories.user_id=users.id " \
            "WHERE categories.id=?"
    cur = con.cursor()
    cur.execute(query, (category_id,))
    category_info = cur.fetchone()
    con.close()
    return render_template('confirm_delete_category.html', category=category_info)


@app.route('/delete_entry/<entry_id>')
def delete_entry(entry_id):
    if not is_admin():
        return redirect("/")
    else:
        con = connect(DATABASE)
        query = "DELETE FROM entries " \
                "WHERE entries.id=?"
        cur = con.cursor()
        cur.execute(query, (entry_id,))
        con.commit()
        con.close()
        flash("The entry has been deleted.")
        return redirect("/")


@app.route('/delete_category/<category_id>')
def delete_category(category_id):
    if not is_admin():
        return redirect("/")
    else:
        con = connect(DATABASE)
        query = "DELETE FROM categories " \
                "WHERE categories.id=?"
        cur = con.cursor()
        cur.execute(query, (category_id,))
        con.commit()
        con.close()
        flash("The category has been deleted.")
        return redirect("/admin")


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
