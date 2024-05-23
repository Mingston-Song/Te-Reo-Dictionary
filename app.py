from flask import Flask, render_template, redirect, request, session, flash
import sqlite3
from flask_bcrypt import Bcrypt

# E:/Min/School Work/DTS/Te-Reo-Dictionary/database.db
DATABASE = "database.db"  # file path to the database
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "w3wkjdxdckiup0i21like6785to30182eat5786982dogs1902858and1239842cats47uyhxnhjdcvgf"
# key used to secure session data


def connect(db_file):
    # creates a connection with the database
    # inputs: database file path
    # outputs: connection, prints the error

    try:
        connection = sqlite3.connect(db_file)
        return connection
    except sqlite3.Error as e:
        print(e)
    return None


@app.context_processor
def logged_in_context_processor():
    # makes the logged_in function callable in jinja

    return dict(logged_in=logged_in)


def logged_in():
    # checks whether you are logged in by checking if user_id exists in session tuple
    # inputs: user id
    # outputs: true or false

    if session.get("user_id"):
        return True
    else:
        return False


@app.context_processor
def is_admin_context_processor():
    # makes the is_admin function callable in jinja

    return dict(is_admin=is_admin)


def is_admin():
    # checks whether the user is an admin
    # inputs: whether the user is logged in, account type
    # outputs: true or false

    if logged_in() and session.get("type") == 1:
        return True
    else:
        return False


@app.route('/')
def render_home():
    # default page the user is greeted with and redirected to

    return render_template('home.html')


@app.route('/no_results')
def render_no_results():
    # page for no results
    # outputs: no results page

    return render_template('no_results.html')


@app.route('/database/<category_id>')
def render_database_categories(category_id):
    # renders the database page and its corresponding entries
    # inputs: id of category filter
    # outputs: no results page, database page with list of entries, list of categories, id of category filter

    con = connect(DATABASE)
    cur = con.cursor()
    if category_id == '-1':
        # if no category filter (-1 is the default id for showing all the entries as there will never be a category id
        # of -1)
        query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, " \
                "categories.name " \
                "FROM entries " \
                "INNER JOIN categories ON entries.category_id=categories.id " \
                "ORDER BY entries.date DESC "
        cur.execute(query)
    else:
        # if a category filter is in effect
        query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, " \
                "categories.name " \
                "FROM entries " \
                "INNER JOIN categories ON entries.category_id=categories.id " \
                "WHERE category_id=? " \
                "ORDER BY entries.date DESC "
        cur.execute(query, (category_id,))
    entry_list = cur.fetchall()  # stores information on all the entries that will be displayed
    query = "SELECT id, name " \
            "FROM categories " \
            "ORDER BY date ASC "
    cur.execute(query)
    category_list = cur.fetchall()  # stores information on all the categories to be displayed in the filters
    con.close()
    if len(entry_list) == 0:
        # if no entries are displayed
        return redirect("/no_results")
    else:
        return render_template('database.html', entries=entry_list, categories=category_list, id=int(category_id))


@app.route('/search', methods=['GET', 'Post'])
def render_search():
    # renders the database with results from the searchbar
    # inputs: searchbar query
    # outputs: no results page, database page with list of entries, list of categories, id of category filter

    search = "%" + request.form['search'] + "%"  # the % signs include anything with the query inside of it
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id " \
            "WHERE (entries.maori LIKE ? or entries.english LIKE ? or entries.level LIKE ?) " \
            "ORDER BY entries.date DESC "
    con = connect(DATABASE)
    cur = con.cursor()
    cur.execute(query, (search, search, search))  # searches in maori, english, and level
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
    # renders entry indepth information page
    # inputs: id of the entry
    # outputs: no results page, entry details page with information on the entry

    con = connect(DATABASE)
    cur = con.cursor()
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name, " \
            "entries.image, users.f_name, users.l_name, entries.date " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id " \
            "INNER JOIN users ON entries.user_id=users.id " \
            "WHERE entries.id=?"
    cur.execute(query, (entry_id,))
    entry_info = cur.fetchone()  # stores information on the entry with the matching entry id
    con.close()
    if not entry_info:
        # if no entry with matching entry id
        return redirect("/no_results")
    return render_template('entry.html', entry=entry_info)


@app.route('/login', methods=["POST", "GET"])
def render_login():
    # renders the login page and deals with login form details
    # inputs: logged in status, request method, email, password
    # outputs: login page, home redirect, messages, stores session details as a dict in cookies

    if logged_in():
        return redirect("/")
    if request.method == "POST":
        # if information from a form which uses the method "POST" and action "/login" is received
        print(request.form)
        email = request.form["email"].strip().lower()  # emails are not case-sensitive so are stored in lowercase
        password = request.form["password"]  # passwords should not be stripped as they have been confirmed by the user
        con = connect(DATABASE)
        cur = con.cursor()
        query = "SELECT id, password, f_name, l_name, type " \
                "FROM users " \
                "WHERE email = ?"
        cur.execute(query, (email,))
        user_data = cur.fetchone()  # stores information on the user with the email
        con.close()
        try:
            # tries to store each bit of the user data into their respective dict keywords
            user_id = user_data[0]
            f_name = user_data[2]
            l_name = user_data[3]
            hashed_password = user_data[1]
        except TypeError:
            # if the user data is none, a type error will be returned, and it means there is no user with a matching
            # email
            flash('An account with this email does not exist.')
            # uses flask's flash module to pass an error message to the html
            return redirect("/login")
        if not bcrypt.check_password_hash(hashed_password, password):
            # checks if the password does not match
            flash('Your password is incorrect.')
            return redirect("/login")
        session['email'] = email
        session['user_id'] = user_id
        session['f_name'] = f_name
        session['l_name'] = l_name
        session['type'] = user_data[4]  # account type
        print(session)
        return redirect("/")
    return render_template('login.html')


@app.route('/logout')
def logout():
    # empties the session and redirects to login
    # inputs: session keys
    # outputs: login redirect, messages, empties session dict

    for key in list(session.keys()):
        session.pop(key)
    flash('You have successfully logged out.')
    return redirect("/login")


@app.route('/signup', methods=["POST", "GET"])
def render_signup_page():
    # renders the signup page and deals with signup form details
    # inputs: logged in status, first name, last name, email, password, confirm password, account type
    # outputs: signup page, home redirect, login redirect, messages,

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
        hashed_password = bcrypt.generate_password_hash(password)  # hashes password with bcrypt
        con = connect(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO users (f_name, l_name, email, password, type) " \
                "VALUES (?, ?, ?, ?, ?)"
        try:
            cur.execute(query, (f_name, l_name, email, hashed_password, account_type))
        except sqlite3.IntegrityError:
            # as the email column has a unique restriction, submitting an existing email would cause an integrity error
            con.close()
            flash("This email has already been used.")
            return redirect("/signup")
        con.commit()
        con.close()
        return redirect("/login")
    return render_template('signup.html')


@app.route('/admin')
def render_admin_page():
    # renders the admin page
    # inputs: admin status
    # outputs: admin page with list of categories

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
    # deals with add entry form
    # inputs: admin status, maori word, english word, definition, level, category id, user id, request method
    # outputs: home redirect, admin page redirect, messages

    if not is_admin():
        return redirect("/")
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
    # deals with add category form
    # inputs: admin status, category name, user id, request method
    # outputs: messages, home redirect, admin redirect

    if not is_admin():
        return redirect("/")
    if request.method == "POST":
        print(request.form)
        category_name = request.form.get("cat_name").lower().strip()
        user_id = session.get("user_id")
        con = connect(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO categories (name, user_id) " \
                "VALUES (?, ?)"
        try:
            cur.execute(query, (category_name, int(user_id)))
        except sqlite3.IntegrityError:
            # as category name has a unique restriction
            con.close()
            flash("A category with this name already exists.")
            return redirect("/admin")
        con.commit()
        con.close()
        flash("Your category has been added.")
        return redirect("/")


@app.route('/confirm_delete_entry/<entry_id>')
def render_confirm_delete_entry_page(entry_id):
    # renders delete entry confirmation page
    # inputs: admin status, id of entry being deleted
    # outputs: confirmation page with info on the entry, messages, home redirect

    if not is_admin():
        return redirect("/")
    con = connect(DATABASE)
    cur = con.cursor()
    query = "SELECT entries.id, entries.maori, entries.english, entries.definition, entries.level, categories.name, " \
            "entries.image, users.f_name, users.l_name, entries.date, users.id " \
            "FROM entries " \
            "INNER JOIN categories ON entries.category_id=categories.id " \
            "INNER JOIN users ON entries.user_id=users.id " \
            "WHERE entries.id=?"
    cur.execute(query, (entry_id,))
    entry_info = cur.fetchone()
    con.close()
    if int(entry_info[10]) == 1:
        # if the creator of the entry is user 1
        flash("You cannot delete a default entry.")
        return redirect("/")
    return render_template('confirm_delete_entry.html', entry=entry_info)


@app.route('/confirm_delete_category/<category_id>', methods=["POST", "GET"])
def render_confirm_delete_category_page(category_id):
    # renders delete category confirmation page
    # inputs: admin status, id of category being deleted, request method
    # outputs: confirmation page with info on the category, messages, home redirect, admin redirect

    if not is_admin():
        return redirect("/")
    if request.method == "POST":
        # if the user has submitted a delete category form the default url is <category_id> = -1
        print(request.form)
        return redirect(f'/confirm_delete_category/{request.form.get("cat_id")}')
        # redirects to url with right cateogry id
    con = connect(DATABASE)
    cur = con.cursor()
    query = "SELECT categories.id, categories.name, users.f_name, users.l_name, categories.date, users.id " \
            "FROM categories " \
            "INNER JOIN users ON categories.user_id=users.id " \
            "WHERE categories.id=?"
    cur.execute(query, (category_id,))
    category_info = cur.fetchone()
    if int(category_info[5]) == 1:
        # if creator of the category is user 1
        con.close()
        flash("You cannot delete a default category.")
        return redirect("/admin")
    query = "SELECT category_id " \
            "FROM entries " \
            "WHERE category_id=?"
    cur.execute(query, (category_id,))
    if cur.fetchall():
        # if there are any entries under this category
        con.close()
        flash("Please delete the entries under this category first.")
        return redirect("/")
    con.close()
    return render_template('confirm_delete_category.html', category=category_info)


@app.route('/delete_entry/<entry_id>')
def delete_entry(entry_id):
    # deletes an entry
    # inputs: admin status, id of entry being deleted
    # outputs: home redirect, messages

    if not is_admin():
        return redirect("/")
    con = connect(DATABASE)
    cur = con.cursor()
    query = "SELECT id " \
            "FROM entries " \
            "WHERE id=?"
    cur.execute(query, (entry_id,))
    if not cur.fetchone():
        # if no entry with matching id
        flash("This entry doesn't exist.")
        return redirect("/")
    query = "SELECT user_id " \
            "FROM entries " \
            "WHERE id=?"
    cur.execute(query, (entry_id,))
    if cur.fetchone()[0] == 1:
        # if creator of the entry is user 1
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
    # deletes a category
    # inputs: id of category being deleted, admin status
    # outputs: home redirect, messages

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
            # if no category with matching id
            flash("This category doesn't exist.")
            return redirect("/")
        query = "SELECT user_id " \
                "FROM categories " \
                "WHERE id=?"
        cur.execute(query, (category_id,))
        if cur.fetchone()[0] == 1:
            # if creator of the category is user 1
            flash("You cannot delete a default category.")
            return redirect("/")
        query = "SELECT category_id " \
                "FROM entries " \
                "WHERE category_id=?"
        cur.execute(query, (category_id,))
        if cur.fetchall():
            # if there are entries under the category
            flash("Please delete the entries under this category first.")
            return redirect("/")
        query = "DELETE FROM categories " \
                "WHERE categories.id=?"
        cur.execute(query, (category_id,))
        con.commit()
        con.close()
        flash("The category has been deleted.")
        return redirect("/")


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
