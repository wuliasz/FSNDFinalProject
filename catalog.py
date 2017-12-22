from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
#from database_setup import Base, Restaurant, MenuItem, User
from models import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"


## Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()







# THIS SECTION FOR TESTING... WILL BE REMOVED....
# Show all restaurants
@app.route('/restaurant/')
def showRestaurants():
    return "you picked restaurants"


@app.route('/restaurant/<passedString>')
def showString(passedString):
    return "testing - you sent this string: %s " % passedString


@app.route('/restaurant/<int:passedInt>')
def showInt(passedInt):
    return "testing - you sent this integer:  %s " % passedInt









@app.route('/')
@app.route('/catalog')
def showCategories():
    #pull all categories in the table.
    categories = session.query(Category).all()
    #display them using the template.
    return render_template('categoriesAndLatestItem.html', categories=categories, session=login_session)

#        username = login_session['username'],
#        sessprovider = login_session['provider'])
# was sending login_session.  i don't want to do that anymore.     session=login_session)


@app.route('/catalog/newCategory', methods=['GET', 'POST'])
def addNewCategory():
    if 'email' not in login_session:
            return redirect('/showLogin')
    if request.method == 'POST':
        #
        # development response... for now...
        #response = make_response(json.dumps('Add New Category - Post behavior not yet defined.'), 200)
        #response.headers['Content-Type'] = 'application/json'
        #return response
        #
        newCategory = Category(name=request.form['name'], ownerEmail=login_session['email'])
        session.add(newCategory)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')



@app.route('/catalog/<category>/Items')
def showItemsInCategory(category):
    category = session.query(Category).filter_by(name=category).one()
    items = session.query(Item).filter_by(category_id = category.id).all()
    return render_template('itemsInCategory.html', category=category, items=items)


@app.route('/catalog/<category>/<item>')
def showItemDescription(category, item):
    #show the description of the item in the specified category
    return "show the description of item, %s in the %s category" % (item, category)


@app.route('/category/<category>/Items/new', methods=['GET', 'POST'])
def addNewItem(category):
    if request.method == 'POST':
        #newCategory = Category(name=request.form['name'])
        #session.add(newCategory)
        #session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    #return render_template('login.html', STATE=state)
    return render_template('loginLocal.html', STATE=state, message='')


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        print(" FLOW EXCHANGE ERROR ")
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    #12/15/17 I am forcing the values to be reset with each login.
    #         i had a problem while testing, where i could NOT
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    print(" ")
    print(" printing answer.json(): ")
    print(answer.json())
    print(" ")

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(username=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response




# BEGIN BAGEL SHOP TESTING v v v v v v v v v

@auth.verify_password
def verify_password(username, password):
    print "Looking for user %s" % username
    user = session.query(User).filter_by(username = username).first()
    if not user:
        print "User not found"
        return False
    elif not user.verify_password(password):
        print "Unable to verfy password"
        return False
    else:
        g.user = user
        return True


@app.route('/users', methods = ['POST'])
def new_user():
    login_session['email'] = ""
    if request.form['state'] != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    #this is how udacity did it:
    #username = request.get_json('username')
    #password = request.get_json('password')
    #email = request.get_json('email')
    #
    #this is how i got it to work using postman
    #username = request.json['username']
    #password = request.json['password']
    #email = request.json['email']
    #
    #this is how I WILL do it - with a form
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']

    if username is None or password is None or email is None:
        print "missing arguments"
        abort(400)

    #if session.query(User).filter_by(username = username).first() is not None:
    if session.query(User).filter_by(email = email).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message':'user already exists'}), 200#, {'Location': url_for('get_user', id = user.id, _external = True)}

    user = User(username = username, email = email)
    user.hash_password(password)
    session.add(user)
    session.commit()
    #return jsonify({ 'username': user.username }), 201#, {'Location': url_for('get_user', id = user.id, _external = True)}
    login_session['email'] = email
    login_session['provider'] = "local"
    login_session['username'] = username
    return redirect(url_for('showCategories'))



@app.route('/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})



#@app.route('/emailLogin', methods=['GET','POST'])
@app.route('/emailLogin', methods=['POST'])
def emailLogin():
    login_session['email'] = ""
    if request.form['state'] != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    if request.method == 'POST':
        print("Looking for email %s" % request.form['email'])
        user = session.query(User).filter_by(email=request.form['email']).one()
        if not user:
            print "User not found"
            return False
            #redirect to the NEW USER PAGE
            #return redirect(url_for('showCategories'))
        elif not user.verify_password(request.form['password']):
            print("Unable to verIfy password")
            return render_template('loginLocal.html', STATE=state, message="Incorrect Password")
        else:
            print("Password verified for %s " % user.email)
            login_session['email'] = user.email
            login_session['provider'] = "local"
            login_session['username'] = user.username
            # WHAT IS THIS?  g.user = user
            return redirect(url_for('showCategories'))
    else:
        return render_template('loginLocal.html', STATE=state, message = "")


@app.route('/emailLoginNew', methods = ['POST'])
def emailLoginNew():
    if request.form['state'] != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    return render_template('loginLocalNew.html', STATE=request.form['state'], message = "Create a New Login")



@app.route('/emailDisconnect')
def disconnectLocal():
    login_session['email'] = ""
    login_session['provider'] = ""
    login_session['username'] = ""
    return redirect(url_for('showCategories'))

#@app.route('/users/<email>')
#def get_user(email):
#    if not user:
#        abort(400)
#    return jsonify({'username': user.username})







@app.route('/resource')
@auth.login_required
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user.username })

#@app.route('/bagels', methods = ['GET','POST'])
#@auth.login_required
#def showAllBagels():
#    if request.method == 'GET':
#        bagels = session.query(Bagel).all()
#        return jsonify(bagels = [bagel.serialize for bagel in bagels])
#    elif request.method == 'POST':
#        name = request.json.get('name')
#        description = request.json.get('description')
#        picture = request.json.get('picture')
#        price = request.json.get('price')
#        newBagel = Bagel(name = name, description = description, picture = picture, price = price)
#        session.add(newBagel)
#        session.commit()
#        return jsonify(newBagel.serialize)


# END   BAGEL SHOP TESTING ^ ^ ^ ^ ^ ^ ^ ^ ^






#MUST INCLUDE A LOGIN
#MUST RECOGNIZE A LOGGED IN STATE.

#must allow editing..
#the description implies that item names are unique
#i think it's a deliberate mistake.


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)