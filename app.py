from flask import Flask, render_template, request, redirect, url_for
import srp
from client import ClientAuth as ca
from server import ServerAuth as sa

# create the application object
app = Flask(__name__)

# use decorators to link the function to a url
@app.route('/success')
def success():
    return "Success!!"

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if send_cred(request.form['username'], request.form['password']):
            return redirect(url_for('success'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)

def send_cred(username, password):
    ca.testuser = username
    ca.testpassword = password
    sa.usr, sa.s, sa.B = ca.client_send(ca)
    ca.M = sa.process_challenge(sa)
    sa.HAMK = ca.verify_session(ca)
    sa.verify_session(sa)
    if (sa.usr.authenticated() and ca.svr.authenticated()):
        return True

# start the server with the 'run()' method
if __name__ == '__main__':
    app.run(debug=True)
