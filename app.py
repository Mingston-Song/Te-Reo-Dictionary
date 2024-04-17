from flask import Flask, render_template, redirect, request, session
import sqlite3
from flask_bcrypt import Bcrypt


DATABASE = "database.db"
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "kkjsdlrft5uew2wweruyeou9iweqriurrmionmu9buhybvt7tfrct5rxcerxsweqa2qa3was5etdc6rv67tgb8yyh98n9nm0imj0ijku9uh7vgb6t7f6fd56d54"


def connect(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except sqlite3.Error as e:
        print(e)
    return None


@app.route('/')
def render_home():
    return render_template('home.html')


@app.route('/database')
def render_database():
    con = connect(DATABASE)
    query = "SELECT entries.maori, entries.english, entries.definition, entries.level, categories.name FROM entries INNER JOIN categories ON entries.category_id=categories.id"
    cur = con.cursor()
    cur.execute(query)
    entry_list = cur.fetchall()
    query = "SELECT id, name FROM categories"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return render_template('database.html', entries=entry_list, categories=category_list)


@app.route('/database/<category_id>')
def render_database_categories(category_id):
    con = connect(DATABASE)
    query = "SELECT entries.maori, entries.english, entries.definition, entries.level, categories.name FROM entries INNER JOIN categories ON entries.category_id=categories.id WHERE category_id=?"
    cur = con.cursor()
    cur.execute(query, (category_id,))
    entry_list = cur.fetchall()
    query = "SELECT id, name FROM categories"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return render_template('database.html', entries=entry_list, categories=category_list)


@app.route('/login', methods=["POST", "GET"])
def render_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"].strip()
        con = connect(DATABASE)
        query = "SELECT id, password, f_name, l_name, type FROM users WHERE email = ?"
        cur = con.cursor()
        cur.execute(query, (email, ))
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


@app.route('/signup', methods=["POST", "GET"])
def render_signup_page():
    if request.method == "POST":
        print(request.form)
        f_name = request.form.get("f_name").title().strip()
        l_name = request.form.get("l_name").title().strip()
        email = request.form.get("email").lower().strip()
        password = request.form.get("password")
        password2 = request.form.get("password2")
        teacher = request.form.get("type")
        account_type = 0
        if teacher == 'on':
            account_type = 1
        if password != password2:
            return redirect("/signup?error=Passwords+do+not+match")
        hashed_password = bcrypt.generate_password_hash(password)
        con = connect(DATABASE)
        query = "INSERT INTO users (f_name, l_name, email, password, type) VALUES (?, ?, ?, ?, ?)"
        cur = con.cursor()
        try:
            cur.execute(query, (f_name, l_name, email, hashed_password, account_type))
        except sqlite3.IntegrityError:
            con.close()
            return redirect("/signup?error=Email+is+already+used")
        con.commit()
        con.close()
        return redirect("/login")
    return render_template('signup.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
