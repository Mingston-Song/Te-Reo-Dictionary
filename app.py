from flask import Flask, render_template, redirect, request, session
import sqlite3
from flask_bcrypt import Bcrypt

DATABASE = "C:/Users/20392/OneDrive - Wellington College/Smile/smile.db"
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
