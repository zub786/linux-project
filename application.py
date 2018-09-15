from flask import (Flask, render_template, request, redirect,
                   jsonify, url_for, flash, g,
                   session as login_session, make_response)
from sqlalchemy import create_engine, asc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User
from sqlalchemy import func
import string
import random
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer,
                         BadSignature, SignatureExpired)
from functools import wraps

Base = declarative_base()
secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in xrange(32))
app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalogapp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            print('exist ' + str(login_session.get('username')))
            return f(*args, **kwargs)
        else:
            flash('You are not allowed to access there')
            return redirect('/login')
    return decorated_function


# Error Page
@app.route('/error')
def Error():
    return render_template('_Error.html')


# Authentication and Authorization Started

# Create anti-forgery state token and render login page
@app.route('/login', methods=['GET', 'POST'])
def showLogin():
    try:
        session = DBSession()
        if request.method == 'GET':
            state = ''.join(random.choice(
                string.ascii_uppercase + string.digits)
                            for x in xrange(32))
            login_session['state'] = state
            # return "The current session state is %s" % login_session['state']
            return render_template('login.html', STATE=state)
        elif request.method == 'POST':
            email = request.form.get('username')
            password = request.form.get('password')
            user = session.query(User).filter_by(email=email).first()
            if user:
                if user.verify_password(password):
                    login_session['logged_in'] = True
                    login_session['username'] = user.username
                    login_session['picture'] = user.picture
                    login_session['email'] = user.email
                    login_session['provider'] = 'app'
                    login_session['user_id'] = user.id
                    return redirect('/')
                return render_template('loginAgain.html',
                                       Message="Invalid Password")
            else:
                return render_template('loginAgain.html',
                                       Message="User Not Found!")
    except Exception, e:
        return redirect('/error')


# Create anti-forgery state token and render login page
@app.route('/logout')
def logout():
    try:
        if login_session.get('provider') == 'facebook':
            fbdisconnect()
        elif login_session.get('provider') == 'gplus':
            gdisconnect()
        login_session.clear()
        return redirect('/')
    except Exception, e:
        return redirect('/error')


# Render signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    try:
        session = DBSession()
        if request.method == 'GET':
            return render_template('signup.html')
        else:
            user = User()
            isExist = session.query(User).filter_by(
                email=request.form.get('username')).all()
            if(isExist.__len__() == 0):
                user.username = request.form.get('displayName')
                user.email = request.form.get('username')
                user.hash_password(request.form.get('password'))
                user.picture = '/static/blank_user.gif'
                session = DBSession()
                session.add(user)
                session.commit()
                newUser = session.query(User).filter_by(
                    email=request.form.get('username')).one_or_none()
                return render_template('signupDone.html',
                                       SuccessMessage=request.form.get("""'displ
                                       ayName'"""))
            else:
                return render_template('signupAgain.html',
                                       Message="""Sorry! user already exist
                                       against this email address""")
    except Exception, e:
        return redirect('/error')


@app.route('/gconnect', methods=['POST'])
def gconnect():
    try:
        # Validate state token
        if request.args.get('state') != login_session['state']:
            print(request.args.get('state'))
            response = make_response(
                json.dumps('Invalid state parameter.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        # Obtain authorization code
        code = request.data

        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets(
                'client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(
                json.dumps(
                    'Failed to upgrade the authorization code.'), 401)
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
                json.dumps("""Token's user ID doesn't
                match given user ID."""), 401)
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
        if stored_access_token is not None and gplus_id == stored_gplus_id:
            response = make_response(
                json.dumps('Current user is already connected.'),
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
        login_session['logged_in'] = True
        login_session['username'] = data['name']
        login_session['picture'] = data['picture']
        login_session['email'] = data['email']
        login_session['provider'] = 'gplus'
        uid = getUserID(data['email'])
        if uid is None:
            uid = createUser(login_session)
        login_session['user_id'] = uid

        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']
        output += '!</h1>'
        output += '<img src="'
        output += login_session['picture']
        output += """' " style = "width: 150px; height: 150px;border-radius: 100px;
        -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '"""
        flash("you are now logged in as %s" % login_session['username'])
        print "done!" + str(login_session['logged_in'])
        return output
    except Exception, e:
        return redirect('/error')

    # DISCONNECT - Revoke a current user's token and reset their login_session


def createUser(login_session):
    try:
        user = User(username=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
        session = DBSession()
        session.add(user)
        session.commit()
        newUser = session.query(User).filter_by(
            email=login_session['email']).one_or_none()
        return newUser.id
    except Exception, e:
        return redirect('/error')


def getUserID(user_email):
    try:
        session = DBSession()
        user = session.query(User).filter_by(email=user_email).one_or_none()
        return user.id
    except Exception, e:       
        return None


@app.route('/gdisconnect')
def gdisconnect():
    try:
        access_token = login_session.get('access_token')
        if access_token is None:
            print 'Access Token is None'
            response = make_response(
                json.dumps('Current user not connected.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        print 'In gdisconnect access token is %s', access_token
        print 'User name is: '
        print login_session['username']
        url = """'https://accounts.google.com/
        o/oauth2/revoke?token=%s'""" % access_token
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        print 'result is '
        print result
        if result['status'] == '200':
            del login_session['access_token']
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            response = make_response(
                json.dumps('Successfully disconnected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response
        else:
            response = make_response(
                json.dumps('Failed to revoke token for given user.', 400))
            response.headers['Content-Type'] = 'application/json'
            return response
    except Exception, e:
        return redirect('/error')


# facebook code

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    try:
        if request.args.get('state') != login_session['state']:
            response = make_response(
                json.dumps('Invalid state parameter.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        access_token = request.data
        print "access token received %s " % access_token
        app_id = json.loads(
            open('fb_client_secrets.json', 'r').read())[
            'web']['app_id']
        app_secret = json.loads(
            open('fb_client_secrets.json', 'r').read())['web']['app_secret']
        url = """'https://graph.facebook.com/oauth/access_token?grant_type
        =fb_exchange_token&client_id=%s&client_secret
        =%s&fb_exchange_token=%s'""" % (
            app_id, app_secret, access_token)
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        # Use token to get user info from API
        userinfo_url = "https://graph.facebook.com/v2.8/me"
        '''
            Due to the formatting for the result from 
            the server token exchange we have to
            split the token first on commas and 
            select the first index which gives us 
            the key : value
            for the server access token then we split
            it on colons to pull out the actual token value
            and replace the remaining quotes with nothing
            so that it can be used directly in the graph
            api calls
        '''
        token = result.split(',')[0].split(':')[1].replace('"', '')
        url = """'https://graph.facebook.com/v2.8/me?
        access_token=%s&fields=name,id,email'""" % token
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]

        # print "url sent for API access:%s"% url
        # print "API JSON result: %s" % result
        data = json.loads(result)
        login_session['provider'] = 'facebook'
        login_session['facebook_id'] = data["id"]
        login_session['username'] = data['name']
        login_session['email'] = data['email']
        login_session['logged_in'] = True      

        # The token must be stored in the login_session
        # in order to properly logout
        login_session['access_token'] = token

        # Get user picture
        url = """'https://graph.facebook.com/v2.8/me/picture?
        access_token=%s&redirect=0&height=200&width=
        200'""" % token
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
        output += """' " style = "width: 300px; height: 
            300px;border-radius: 150px;-webkit-border-radius:
                150px;-moz-border-radius: 150px;"> '"""
        flash("Now logged in as %s" % login_session['username'])
        return output
    except Exception, e:
        return redirect('/error')


@app.route('/fbdisconnect')
def fbdisconnect():
    try:
        facebook_id = login_session['facebook_id']
        # The access token must me included to successfully logout
        access_token = login_session['access_token']
        url = """'https://graph.facebook.com/%s/
        permissions?access_token=%s'""" % (
            facebook_id, access_token)
        h = httplib2.Http()
        result = h.request(url, 'DELETE')[1]
        return "you have been logged out"
    except Exception, e:
        return redirect('/error')


# Authentication and Authorization Ended

# JSON APIs to view items of a specific category
@app.route('/category/<int:category_id>/item/JSON')
def categoryitemJSON(category_id):
    try:
        session = DBSession()
        category = session.query(
            Category).filter_by(
                id=category_id).one_or_none()
        items = session.query(Item).filter_by(
            category_id=category_id).all()
        return jsonify(items=[i.serialize for i in items])
    except Exception, e:
        return redirect('/error')


# JSON APIs to view item of a specific category
@app.route('/category/<int:category_id>/item/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    try:
        session = DBSession()
        item = session.query(Item).filter_by(id=item_id).one_or_none()
        return jsonify(item=item.serialize)
    except Exception, e:
        return redirect('/error')


# JSON APIs to view categories
@app.route('/category/JSON')
def categoriesJSON():
    try:
        session = DBSession()
        categories = session.query(Category).all()
        return jsonify(categories=[r.serialize for r in categories])
    except Exception, e:
        return redirect('/error')


# Show all categories Public
@app.route('/')
def showCategories():
    try:
        if login_session.get('logged_in'):
            print(login_session.get('logged_in'))
            session = DBSession()
            categories = session.query(Category).all()
            itemsids = session.query(
                func.max(Item.id)).group_by(
                                            Item.category_id).all()
            itemsidsString = str(
                                itemsids).replace('(', '').replace(')', '')
            items = session.query(Item).filter(
                Item.id.in_(str(
                                itemsidsString).strip('[]'))).all()  
            return render_template(
                                   'categories.html', categories=categories, 
                                   items=items)
        else:
            print(login_session.get('logged_in'))
            session = DBSession()
            categories = session.query(Category).all()
            itemsids = session.query(func.max(
                Item.id)).group_by(Item.category_id).all()
            itemsidsString = str(itemsids).replace('(', '').replace(')', '')
            items = session.query(Item).filter(
                                                Item.id.in_(str(itemsidsString
                                                                ).strip('[]'))
                                                                ).all()  
            return render_template('categoriesPublic.html',
                                   categories=categories, items=items)
    except Exception, e:
        return redirect('/error')

# Create a new category


@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    try:
        session = DBSession()
        if request.method == 'POST':
            newcategory = Category(
                name=request.form['name'],
                createdby=login_session.get('user_id'))
            session.add(newcategory)
            flash("""'New category %s 
            Successfully Created'""" % newcategory.name)
            session.commit()
            return redirect(url_for('showCategories'))
        else:
            return render_template('newCategory.html')
    except Exception, e:
        return redirect('/error')


# Edit a category
@app.route('/category/<int:category_id>/edit/',
           methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    try:
        session = DBSession()
        editedCategory = session.query(
            Category).filter_by(id=category_id).one_or_none()
        if request.method == 'POST':
            if request.form['name']:
                editedCategory.name = request.form['name']
                flash('Category Successfully Edited %s' % editedCategory.name)
                session.add(editedCategory)
                session.commit()
                return redirect(url_for('showCategories'))
        else:
            return render_template('editCategory.html', 
                                   category=editedCategory)
    except Exception, e:
        return redirect('/error')

# Delete a category


@app.route('/category/<int:category_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    try:
        session = DBSession()
        categoryToDelete = session.query(
            Category).filter_by(id=category_id).one_or_none()
        if request.method == 'POST':
            session.delete(categoryToDelete)
            flash('%s Successfully Deleted' % categoryToDelete.name)
            session.commit()
            return redirect(url_for('showCategories',
                                    category_id=category_id))
        else:
            return render_template('deleteCategory.html',
                                   category=categoryToDelete)
    except Exception, e:
        return redirect('/error')


# Show all items of a category
@app.route('/category/<int:category_id>/item',
           methods=['GET'])
def showItems(category_id):
    try:
        if login_session.get('logged_in'):
            session = DBSession()
            category = session.query(
                                    Category).filter_by(
                                        id=category_id
                                        ).one_or_none()
            items = session.query(Item
                                  ).filter_by(category_id=category_id
                                              ).all()
            return render_template('items.html',
                                   items=items, category=category)
        else:
            session = DBSession()
            category = session.query(
                Category).filter_by(id=category_id
                                    ).one_or_none()
            items = session.query(Item).filter_by(
                category_id=category_id).all()
            return render_template('itemsPublic.html',
                                   items=items, category=category)
    except Exception, e:
        return redirect('/error')


# Create a new item 
@app.route('/category/<int:category_id>/item/new', 
           methods=['GET', 'POST'])
@login_required
def newItem(category_id):
    try:
        session = DBSession()
        category = session.query(Category
                                 ).filter_by(
                                            id=category_id
                                            ).one_or_none()
        if request.method == 'POST':
            newItem = Item(name=request.form['name'],
                           description=request.form['description'],
                           price=request.form['price'],
                           category_id=category_id)
            session.add(newItem)
            session.commit()
            flash("""'New %s Item 
            Successfully Created'""" % (newItem.name))
            return redirect(url_for('showItems',
                                    category_id=category_id))
        else:
            return render_template('newItem.html',
                                   category_id=category_id)
    except Exception, e:
        return redirect('/error')


# Edit a item
@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editItem(category_id, item_id):
    try:
        session = DBSession()
        editedItem = session.query(Item).filter(
            Item.id == item_id,
            Item.category_id == category_id
            ).one_or_none()   
        category = session.query(
            Category).filter_by(
                id=category_id).one_or_none()
        if request.method == 'POST':
            if category.createdby == login_session['user_id']:
                if request.form['name']:
                    editedItem.name = request.form['name']
                if request.form['description']:
                    editedItem.description = request.form['description']
                if request.form['price']:
                    editedItem.price = request.form['price']
                session.add(editedItem)
                session.commit()
                flash('Item Successfully Edited')
                return redirect(url_for('showItems', category_id=category_id))
            else:
                flash('Sorry! You have no authority to change in it.')
                return render_template('editItem.html',
                                       category=category, item=editedItem)
        else:
            return render_template('editItem.html',
                                   category=category, item=editedItem)
    except Exception, e:
        return redirect('/error')


# View an item
@app.route('/item/<int:item_id>')
def showItem(item_id):
    try:
        if login_session.get('logged_in'):
            session = DBSession()
            item = session.query(Item).filter_by(id=item_id).one_or_none()
            return render_template('viewItem.html', item=item)
        else:
            session = DBSession()
            item = session.query(Item).filter_by(id=item_id).one_or_none()
            return render_template('viewItemPublic.html', item=item)
    except Exception, e:
        return redirect('/error')


# Delete an item
@app.route('/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(category_id, item_id):
    try:
        session = DBSession()
        category = session.query(
            Category).filter_by(
                id=category_id).one_or_none()
        itemToDelete = session.query(
                                     Item).filter_by(id=item_id
                                                     ).one_or_none()
        if request.method == 'POST':
            if category.createdby == login_session['user_id']:
                session.delete(itemToDelete)
                session.commit()
                flash('Item Successfully Deleted')
                return redirect(url_for('showItems',
                                category_id=category_id))
            else:
                flash('Sorry! You have no authority to change in it')
                return render_template('deleteItem.html',
                                       item=itemToDelete, category=category)
        else:
            return render_template('deleteItem.html',
                                   item=itemToDelete, category=category)
    except Exception, e:
        return redirect('/error')


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)