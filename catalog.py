from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
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
import datetime

auth = HTTPBasicAuth()
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"


## Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


#JSON API for category list
@app.route('/catalog/category/JSON')
def showCategoriesJSON():
    #pull all categories in the table.
    categories = session.query(Category).order_by(asc(Category.name)).all()
    return jsonify(Category=[i.serialize for i in categories])


#JSON API for item list of specific category
@app.route('/catalog/<categoryName>/Items/JSON')
def showItemsInCategoryJSON(categoryName):
    try:
        category = session.query(Category).filter_by(name=categoryName).one()
    except:
        showMessage = "Category '%s' does not exist!" % categoryName
        response = make_response(json.dumps(showMessage), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    items = session.query(Item).filter_by(category_id = category.id).order_by(Item.name).all()
    numberOfItems = len(items)
    return jsonify(Item=[i.serialize for i in items])


@app.route('/')
@app.route('/catalog')
def showCategories():
    #pull all categories in the table.
    categories = session.query(Category).order_by(asc(Category.name)).all()
    items = session.query(Item).order_by(desc(Item.addDate)).limit(6)
    #display them using the template.
    return render_template('categoriesAndLatestItem.html', categories=categories, session=login_session, items=items)


@app.route('/')
@app.route('/catalog/<message>')
def showCategoriesPlus(message):
    #pull all categories in the table.
    categories = session.query(Category).order_by(asc(Category.name)).all()
    items = session.query(Item).order_by(desc(Item.addDate)).limit(6)
    #display them using the template.
    return render_template('categoriesAndLatestItem.html', categories=categories, session=login_session, items=items, message=message)


@app.route('/catalog/newCategory', methods=['GET', 'POST'])
def addNewCategory():
    if 'email' not in login_session:
            return redirect('/login')
    if request.method == 'POST':
        #ensure that the database key value, category.name has been specified before adding it to the table.
        if len(request.form['name']) < 1:
            showMessage = 'Category not added:  name not specified.'
            return redirect(url_for('showCategoriesPlus', message=showMessage))
        try:
            category = session.query(Category).filter_by(name=request.form['name']).one()
            showMessage = 'Category not added: "%s" already exists!' % request.form['name']
            return redirect(url_for('showCategoriesPlus', message=showMessage))
        except:
            newCategory = Category(name=request.form['name'], ownerEmail=login_session['email'])
            session.add(newCategory)
            session.commit()
            return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


@app.route('/catalog/<categoryName>/DeleteCategory', methods=['POST'])
def deleteCategory(categoryName):
    if 'email' not in login_session:
            return redirect('/login')
    category = session.query(Category).filter_by(name=categoryName).one()
    if login_session['email'] != category.ownerEmail:
        return redirect(url_for('showCategories'))
    deleteItems = session.query(Item).filter_by(category_id = category.id).all()
    for item in deleteItems:
        session.delete(item)
        session.commit()
    session.delete(category)
    session.commit()
    return redirect(url_for('showCategories'))


@app.route('/catalog/<category>/Items')
def showItemsInCategory(category):
    try:
        category = session.query(Category).filter_by(name=category).one()
        items = session.query(Item).filter_by(category_id = category.id).order_by(Item.name).all()
        return render_template('itemsInCategory.html', category=category, items=items, itemCount=len(items))
    except:
        showMessage = 'Category "%s" does not exist!' % category
        return redirect(url_for('showCategoriesPlus', message=showMessage))


@app.route('/catalog/<categoryName>/<itemName>/Description')
def showItemDescription(categoryName, itemName):
    #show the description of the item in the specified category
    category = session.query(Category).filter_by(name=categoryName).one()
    item = session.query(Item).filter_by(category_id = category.id, name=itemName).one()
    return render_template('itemDescription.html', item=item, session=login_session, category=category)


@app.route('/category/<categoryName>/Items/new', methods=['GET', 'POST'])
def addNewItem(categoryName):
    category = session.query(Category).filter_by(name=categoryName).one()
    items = session.query(Item).filter_by(category_id = category.id).all()
    if 'email' not in login_session:
            return redirect('/login')
    if request.method == 'POST':
        #ensure that the database key value,name has been specified before adding it to the table.
        if len(request.form['name']) < 1:
            return redirect(url_for('showItemsInCategory', category=category.name))
        try:
            checkItem = session.query(Item).filter_by(
                name=request.form['name'], category_id=category.id).one()
            showMessage = 'Item not added to %s: "%s" already exists!' % (categoryName, request.form['name'])
            return redirect(url_for('showCategoriesPlus', message=showMessage))
        except:
            #picture = Column(String)
            #addDate = Column(DateTime())
            newItem = Item(name=request.form['name'], description=request.form['description'],
                category_id = category.id , addDate = datetime.datetime.now(), ownerEmail=login_session['email'])
            session.add(newItem)
            session.commit()
            return redirect(url_for('showItemsInCategory', category=category.name))
    else:
        return render_template('newItemInCategory.html', category=category, items=items)


@app.route('/catalog/<categoryName>/<itemName>/UpdateDescription', methods=['POST'])
def updateDescription(categoryName, itemName):
    if 'email' not in login_session:
            return redirect('/login')
    category = session.query(Category).filter_by(name=categoryName).one()
    updateItem = session.query(Item).filter_by(category_id = category.id, name=itemName).one()
    updateItem.description = request.form['itemDesc']
    updateItem.addDate = datetime.datetime.now()
    session.add(updateItem)
    session.commit()
    return redirect(url_for('showItemsInCategory', category=category.name))


@app.route('/catalog/<categoryName>/<itemName>/EditDescription')
def editDescription(categoryName, itemName):
    if 'email' not in login_session:
            return redirect('/login')
    category = session.query(Category).filter_by(name=categoryName).one()
    updateItem = session.query(Item).filter_by(category_id = category.id, name=itemName).one()
    return render_template('itemDescriptionModify.html', category=category, item=updateItem, session=login_session)
    return render_template('itemDescription.html', item=item, session=login_session, category=category)


@app.route('/catalog/<categoryName>/<itemName>/DeleteItem', methods=['POST'])
def deleteItem(categoryName, itemName):
    category = session.query(Category).filter_by(name=categoryName).one()
    deleteItem = session.query(Item).filter_by(category_id = category.id, name=itemName).one()
    if 'email' not in login_session:
            return redirect('/login')
    session.delete(deleteItem)
    session.commit()
    return redirect(url_for('showItemsInCategory', category=category.name))


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    #Include google and facebook logins in future release.
    #return render_template('login.html', STATE=state)
    return render_template('loginLocal.html', STATE=state, message='')


#to be included in the future.
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


#to be included in the future.
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


#to be included in the future.
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
    #ensure that the database key value,name has been specified before adding it to the table.
    if len(login_session['username']) < 1:
        return redirect(url_for('showItemsInCategory', category=category.name))

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


#to be included in the future.
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
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']

    if username is None or password is None or email is None:
        print "missing arguments"
        abort(400)

    if session.query(User).filter_by(email = email).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message':'user already exists'}), 200#, {'Location': url_for('get_user', id = user.id, _external = True)}

    user = User(username = username, email = email)
    user.hash_password(password)
    session.add(user)
    session.commit()

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


@app.route('/emailLogin', methods=['POST'])
def emailLogin():
     login_session['email'] = ""
     if request.form['state'] != login_session['state']:
          response = make_response(json.dumps('Invalid state parameter.'), 401)
          response.headers['Content-Type'] = 'application/json'
          return response
     if request.method == 'POST':
          print("Looking for email %s" % request.form['email'])
          try:
               user = session.query(User).filter_by(email=request.form['email']).one()
          except Exception:
               return render_template('loginLocalNew.html', STATE=login_session['state'], message = "User %s not defined" % request.form['email'])

          if not user:
               print "User not found"
               return False
               # redirect to the NEW USER PAGE
               # return redirect(url_for('showCategories'))
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


@app.route('/resource')
@auth.login_required
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user.username })


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)