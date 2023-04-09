from flask import Flask, render_template, request, redirect
from password_manager import PasswordManager

app = Flask(__name__)
salt = 'my-random-salt'
pm = PasswordManager("my-secret-password", salt)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        pm.add_password(website, username, password)
        return redirect('/')
    else:
        return render_template('add_password.html')


@app.route('/get_password', methods=['GET', 'POST'])
def get_password():
    if request.method == 'POST':
        website = request.form['website']
        try:
            username, password = pm.get_password(website)
            return render_template('get_password.html', username=username, password=password)
        except KeyError:
            error_message = f"No password found for website: {website}"
            return render_template('error.html', message=error_message)
    else:
        return render_template('get_password.html')


if __name__ == '__main__':
    app.run(debug=True)
