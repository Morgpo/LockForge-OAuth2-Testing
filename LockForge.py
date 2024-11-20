from flask import Flask, render_template, request, redirect, url_for, flash, session
from cryptography.fernet import Fernet
import os
import json
import base64
import hashlib
import secrets
import string
import dropbox

app = Flask(__name__)
app.secret_key = 'c684d8433efeefba0c6457cb3b2059469c137cc75abaaff23ec8e9502cd2801f'

# Setup paths
LOCKFORGE_PATH = "NOT IMPLEMENTED"
KEY_FILE = "NOT IMPLEMENTED"
LOCAL_KEY_FILE = "NOT IMPLEMENTED"

# Dropbox app credentials
DROPBOX_APP_KEY = 'jfemooqcfxfmja5'
DROPBOX_APP_SECRET = '55ksdub5976d2xu'
DROPBOX_REDIRECT_URI = 'http://localhost:5000/dropbox_callback'

# NOT IMPLEMENTED
def load_key():
    pass

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

class FlaskSessionStorage:
    def __init__(self, session):
        self.session = session

    def __getitem__(self, key):
        return self.session.get(key)

    def __setitem__(self, key, value):
        self.session[key] = value

    def __delitem__(self, key):
        if key in self.session:
            del self.session[key]

    def get(self, key, default=None):
        return self.session.get(key, default)

dbx_flow = dropbox.DropboxOAuth2Flow(
    consumer_key=DROPBOX_APP_KEY,
    consumer_secret=DROPBOX_APP_SECRET,
    redirect_uri=DROPBOX_REDIRECT_URI,
    session=FlaskSessionStorage(session),
    csrf_token_session_key="dropbox-auth-csrf-token"
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/save', methods=['GET', 'POST'])
def save_account():
    # redirect to Dropbox login if not logged in
    if 'dropbox_access_token' not in session:
        flash('Please log in to Dropbox first.')
        return redirect(url_for('dropbox_login'))

    if request.method == 'POST':
        account_name = request.form['account_name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        misc_notes = request.form['misc_notes']
        data = {
            "Username": username,
            "Email": email,
            "Password": password,
            "Misc Notes": misc_notes
        }
        save_account_to_dropbox(account_name, data)
        flash('Account saved successfully!')
        return redirect(url_for('index'))
    return render_template('save.html')

@app.route('/manage')
def manage_accounts():
    # redirect to Dropbox login if not logged in
    if 'dropbox_access_token' not in session:
        flash('Please log in to Dropbox first.')
        return redirect(url_for('dropbox_login'))
    
    accounts = []
    for filename in os.listdir(LOCKFORGE_PATH):
        if filename.endswith(".json"):
            account_name = filename[:-5]
            accounts.append(account_name)
    return render_template('manage.html', accounts=accounts)

@app.route('/retrieve/<account_name>') # NOT IMPLEMENTED
def retrieve_account(account_name):
    key = load_key()
    filename = os.path.join(LOCKFORGE_PATH, f"{account_name}.json")
    if os.path.exists(filename):
        with open(filename, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = decrypt_data(encrypted_data, key)
        account_data = json.loads(decrypted_data)
        return render_template('retrieve.html', account_data=account_data)
    else:
        flash('No data found for account: ' + account_name)
        return redirect(url_for('manage_accounts'))

@app.route('/dropbox_login') # ERROR CHECKING
def dropbox_login(): 
    authorize_url = dbx_flow.start()
    return redirect(authorize_url)

@app.route('/dropbox_callback')
def dropbox_callback():
    print("Entered dropbox_callback")
    try:
        print("Attempting to finish OAuth flow")
        print("Request args:", request.args)  # Debugging line to print request arguments
        csrf_token = session.get("dropbox-auth-csrf-token")
        print("Session CSRF token:", csrf_token)  # Debugging line to print CSRF token from session
        oauth_result = dbx_flow.finish(request.args) # NEVER LOADS
        print("OAuth flow finished")
        access_token = oauth_result.access_token
        user_id = oauth_result.user_id
        url_state = oauth_result.url_state
        session['dropbox_access_token'] = access_token
        flash('Dropbox login successful!')
        print('Dropbox login successful!')

        # Setup LockForge path and key file after Dropbox login
        if not os.path.exists(LOCKFORGE_PATH):
            os.makedirs(LOCKFORGE_PATH)
            print(f'Created directory: {LOCKFORGE_PATH}')
        if not os.path.exists(KEY_FILE):
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as key_file:
                key_file.write(key)
            print(f'Created key file: {KEY_FILE}')

    except dropbox.oauth.BadRequestException as e:
        flash('Bad request: {}'.format(e))
        print('Bad request:', e)
    except dropbox.oauth.BadStateException as e:
        flash('Bad state: {}'.format(e))
        print('Bad state:', e)
    except dropbox.oauth.CsrfException as e:
        flash('CSRF error: {}'.format(e))
        print('CSRF error:', e)
    except dropbox.oauth.NotApprovedException as e:
        flash('Not approved: {}'.format(e))
        print('Not approved:', e)
    except dropbox.oauth.ProviderException as e:
        flash('Provider error: {}'.format(e))
        print('Provider error:', e)
    except Exception as e:
        flash('An unexpected error occurred: {}'.format(e))
        print('Unexpected error:', e)
    
    print("Redirecting to index")
    return redirect(url_for('index'))

# NOT IMPLEMENTED
def save_account_to_dropbox(account_name, data): 
    pass

if __name__ == '__main__':
    app.run(debug=True)