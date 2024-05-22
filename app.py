from flask import Flask, render_template, redirect, request, session, flash
import sqlite3
from flask_bcrypt import Bcrypt
import datetime

# E:/Min/School Work/DTS/Te-Reo-Dictionary/database.db
DATABASE = "database.db"  # file path to the database
app = Flask(__name__)
bcrypt = Bcrypt(app)  # initialising bcrypt
app.secret_key = "w3wkjdxdckiup0i21like6785to30182eat5786982dogs1902858and1239842cats47uyhxnhjdcvgf"  # key used to secure session data


def connect(db_file):  # creates a connection with the database
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except sqlite3.Error as e:
        print(e)
    return None

@app.context_processor
def logged_in_context_processor():  # makes the logged_in function callable in jinja
    return dict(logged_in=logged_in)


def logged_in():  # checks whether you are logged in
    if session.get("user_id"):  # if user_id exists in session tuple to determine whether you are logged in
        return True
    else:
        return False


@app.context_processor
def is_admin_context_processor():  # makes the is_admin function callable in jinja
    return dict(is_admin=is_admin)


def is_admin():  # checks whether you are an admin
    if logged_in() and session.get("type") == 1:  # checks if account type is teacher in session tuple
        return True
    else:
        return False


@app.route('/')
def render_home():  # default page the user is greeted with and redirected to
    return render_template('home.html')


@app.route('/no_results')
def render_no_results():  # page for no results
    return render_template('no_results.html')


@app.route('/database/<category_id>')
def render_database_categories(category_id):
    # renders the database page and its corresponding entries | input: id of the category filter
    # inputs

    con = connect(DATABASE)  # begins database connection
    cur = con.cursor()
    if category_id == '-1':  # if no category filter (database/-1 is the default page for showing all the entries as there will never be a category id of -1)
        query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name " \
                "FROM entries " \
                "INNER JOIN categories ON entries.category_id=categories.id " \
                "ORDER BY entries.date DESC "
        cur.execute(query)  # fetches information on all entries
    else:  # if a category filter is in effect
        query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name " \
                "FROM entries " \
                "INNER JOIN categories ON entries.category_id=categories.id " \
                "WHERE category_id=? "\
                "ORDER BY entries.date DESC "
        cur.execute(query, (category_id, ))  # fetches information on only the entries which match the category filter
    entry_list = cur.fetchall()  # stores information on all the entries that will be displayed
    query = "SELECT id, name " \
            "FROM categories " \
            "ORDER BY date ASC "
    cur.execute(query)  # fetches information on all the categories
    category_list = cur.fetchall()  # stores information on all the categories to be displayed in the filters
    con.close()  # finish database connection
    if len(entry_list) == 0:  # if no entries are displayed
        return redirect("/no_results")  # output: redirect to no results
    else:
        return render_template('database.html', entries=entry_list, categories=category_list, id=int(category_id))  # output: renders database.html passing on the information fetched


@app.route('/search', methods=['GET', 'Post'])  # the get method fetches information from the server and is enabled by default. the post method sends information to the server in this case the searchbar query
def render_search():  # renders the database.html but with results from the searchbar
    search = "%" + request.form['search'] + "%"  # the query and anything with the query inside of it
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id " \
            "WHERE (entries.maori LIKE ? or entries.english LIKE ? or entries.level LIKE ?) " \
            "ORDER BY entries.date DESC "
    con = connect(DATABASE)
    cur = con.cursor()
    cur.execute(query, (search, search, search))  # searches in word maori, word english, and level
    entry_list = cur.fetchall()
    query = "SELECT id, name " \
            "FROM categories " \
            "ORDER BY date ASC "
    cur.execute(query)
    category_list = cur.fetchall()  # fetches categories to be displayed in the filter
    con.close()
    if len(entry_list) == 0:  # if no entries are displayed
        return redirect("/no_results")  # output: redirects to no results page
    else:
        return render_template("database.html", entries=entry_list, categories=category_list, id=-1)  # output: render database.html passing on information on entries matching search results and no category filter


@app.route('/entry/<entry_id>')
def render_entry(entry_id):  # renders the page for indepth information about an entry | input: id of the entry
    con = connect(DATABASE)
    cur = con.cursor()
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name, entries.image, users.f_name, users.l_name, entries.date " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id " \
            "INNER JOIN users ON entries.user_id=users.id " \
            "WHERE entries.id=?"
    cur.execute(query, (entry_id,))
    entry_info = cur.fetchone()  # fetches information on the only entry which matches the entry id
    con.close()
    if not entry_info:  # if no entry with matching entry id
        return redirect("/no_results")  # output: redirect to no results
    return render_template('entry.html', entry=entry_info)  # output: renders entry.html passing on the entry info


@app.route('/login', methods=["POST", "GET"])  # the post method allows the user to submit encrypted information to the server which is useful for confidential forms
def render_login():  # renders the login page
    if logged_in():  # if user is already logged in
        return redirect("/")  # output: redirect to home
    if request.method == "POST":  # if an html form which uses the method "POST" and action "/login" is sent
        email = request.form["email"].strip().lower()  # emails are not case-sensitive so are stored in lowercase. any spaces before and after which should not be recorded are removed using strip
        password = request.form["password"]  # passwords should be stripped as bycrypt hashing ignores spaces before and trailing
        con = connect(DATABASE)
        cur = con.cursor()
        query = "SELECT id, password, f_name, l_name, type " \
                "FROM users " \
                "WHERE email = ?"
        cur.execute(query, (email,))
        user_data = cur.fetchone()  # fetch the information on the user with the email
        con.close()
        try:
            user_id = user_data[0]
            f_name = user_data[2]
            l_name = user_data[3]
            hashed_password = user_data[1]
        except TypeError:  # if the user data is none, a type error will be returned and it means there is no user with matching email
            flash('An account with this email does not exist.')  # uses flask's flash module to pass an error message to the html
            return redirect("/login")  # output: redirect to login and does not start session
        if not bcrypt.check_password_hash(hashed_password, password):  # checks if the password matches the hashed one stored in the database corresponding to the email
            flash('Your password is incorrect.')
            return redirect("/login")  # output: redirects to login and does start session
        session['email'] = email
        session['user_id'] = user_id
        session['f_name'] = f_name
        session['l_name'] = l_name
        session['type'] = user_data[4]
        print(session)  # session stores email, user id, first name, last name, and account type
        return redirect("/")  # output: redirects user to home after starting the session
    return render_template('login.html')  # output: renders login.html


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
        account_type = request.form.get("type")
        if password != password2:
            flash("Passwords do not match.")
            return redirect("/signup")
        hashed_password = bcrypt.generate_password_hash(password)
        con = connect(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO users (f_name, l_name, email, password, type) " \
                "VALUES (?, ?, ?, ?, ?)"
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
    query = "SELECT id, name " \
            "FROM categories " \
            "ORDER BY date ASC"
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
            query = "INSERT INTO entries (maori, english, definition, level, category_id, user_id) " \
                    "VALUES (?, ?, ?, ?, ?, ?)"
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
        query = "INSERT INTO categories (name, user_id) " \
                "VALUES (?, ?)"
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
    cur = con.cursor()
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name, entries.image, users.f_name, users.l_name, entries.date, users.id " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id " \
            "INNER JOIN users ON entries.user_id=users.id " \
            "WHERE entries.id=?"
    cur.execute(query, (entry_id,))
    entry_info = cur.fetchone()
    con.close()
    if int(entry_info[10]) == 1:
        flash("You cannot delete a default entry.")
        return redirect("/")
    return render_template('confirm_delete_entry.html', entry=entry_info)


@app.route('/confirm_delete_category/', methods=["POST", "GET"])
def render_confirm_delete_category_page():
    if not is_admin():
        return redirect("/")
    if request.method == "POST":
        print(request.form)
        category_id = request.form.get("cat_id")
    con = connect(DATABASE)
    cur = con.cursor()
    query = "SELECT categories.id, categories.name, users.f_name, users.l_name, categories.date, users.id " \
            "FROM categories " \
            "INNER JOIN users ON categories.user_id=users.id " \
            "WHERE categories.id=?"
    cur.execute(query, (category_id,))
    category_info = cur.fetchone()
    if int(category_info[5]) == 1:
        con.close()
        flash("You cannot delete a default category.")
        return redirect("/admin")
    query = "SELECT category_id " \
            "FROM entries " \
            "WHERE category_id=?"
    cur.execute(query, (category_id,))
    if cur.fetchall():
        con.close()
        flash("Please delete the entries under this category first.")
        return redirect("/")
    con.close()
    return render_template('confirm_delete_category.html', category=category_info)


@app.route('/delete_entry/<entry_id>')
def delete_entry(entry_id):
    if not is_admin():
        return redirect("/")
    else:
        con = connect(DATABASE)
        cur = con.cursor()
        query = "SELECT id " \
                "FROM entries " \
                "WHERE id=?"
        cur.execute(query, (entry_id,))
        if not cur.fetchone():
            flash("This entry doesn't exist.")
            return redirect("/")
        query = "SELECT user_id " \
                "FROM entries " \
                "WHERE id=?"
        cur.execute(query, (entry_id,))
        if cur.fetchone()[0] == 1:
            flash("You cannot delete a default entry.")
            return redirect("/")
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
        cur = con.cursor()
        query = "SELECT id " \
                "FROM categories " \
                "WHERE id=?"
        cur.execute(query, (category_id,))
        if not cur.fetchone():
            flash("This category doesn't exist.")
            return redirect("/")
        query = "SELECT user_id " \
                "FROM categories " \
                "WHERE id=?"
        cur.execute(query, (category_id,))
        if cur.fetchone()[0] == 1:
            flash("You cannot delete a default category.")
            return redirect("/")
        query = "SELECT category_id " \
                "FROM entries " \
                "WHERE category_id=?"
        cur.execute(query, (category_id,))
        if cur.fetchall():
            flash("Please delete the entries under this category first.")
            return redirect("/")
        query = "DELETE FROM categories " \
                "WHERE categories.id=?"
        cur.execute(query, (category_id,))
        con.commit()
        con.close()
        flash("The category has been deleted.")
        return redirect("/admin")


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
