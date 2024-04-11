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
    query = "SELECT entries.maori, entries.english, entries.definition, entries.image, categories.name FROM entries INNER JOIN categories ON entries.category_id=categories.id"
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
    query = "SELECT entries.maori, entries.english, entries.definition, entries.image, categories.name FROM entries INNER JOIN categories ON entries.category_id=categories.id WHERE category_id=?"
    cur = con.cursor()
    cur.execute(query, (category_id,))
    entry_list = cur.fetchall()
    query = "SELECT id, name FROM categories"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return render_template('database.html', entries=entry_list, categories=category_list)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
