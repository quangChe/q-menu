#!/usr/bin/env python2

# Flask with necessary methods for route handling and logging session data
from flask import Flask, render_template, url_for, request, redirect, flash, \
    jsonify, session as login_session, make_response

# SQLAlchemy for configuring database schema and CRUD operations on the data
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

# Oauth2 to create correct credentials for Google+ and Faceook
# registration and login
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

# Tools for extracting responses from API calls and decoding JSON objects into
# usuable data
import httplib2
import json
import requests

# Generate random values for users' state keys
import random
import string

"""This is a multi-user restaurant app that utilizes flask, PostgresSQL, the
SQLAlchemy ORM and oauth2 for Google+ and Facebook account
authentication/authorization.
"""

app = Flask(__name__)


# Reference client_secrets.json objects as 'CLIENT_ID'
CLIENT_ID = json.loads(
    open('/var/www/html/qmenu/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Quang's Restaurant Menu App"


# Bind database file and configure SQLAlchemy session
engine = create_engine('postgresql+psycopg2://postgres:password@localhost/restaurants')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# ===================================
# HELPER FUNCTIONS FOR ACCOUNT ACCESS
# ===================================

# 1. Create a new user
def createUser(login_session):
    """Function to pull user data from the session to add into database"""
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# 2. Grab user info
def getUserInfo(user_id):
    """Function to grab user info from database using a user id"""
    user = session.query(User).filter_by(id=user_id).one()
    return user


# 3. Check if user exists
def getUserID(email):
    """Function returns a user.id if user is found using email or None if user
    doesn't exist in database. (Use email so that it works with Facebook too).
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# ======================
# LOGIN, SIGNUP, PROFILE
# ======================

@app.route('/login')
def showLogin():
    """Login route to direct users to Google+ or Facebook login prompts
    depending on what they choose
    """

    # Create a state key for current session
    if 'username' not in login_session:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        return render_template('login.html', STATE=state)

    else:
        response = make_response(
            json.dumps('Invalid request made.', 400)
        )
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Route for connecting Google+ User by going through OAuth flow,
    providing credentials and retrieving and storing user data sent back from
    from Google+ API
    """

    # Validate state key
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # Obtain authorization code
        code = request.data
        try:
            # Exchange authorization code for credentials object
            oauth_flow = flow_from_clientsecrets('/var/www/html/qmenu/client_secrets.json',
                                                 scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)

        # Handle any errors from flow exchange
        except FlowExchangeError:
            response = make_response(
                json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify token with Google+ API
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])

        # Handle for error with Google+ API token verification
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the token belongs to the user currently logging in
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            response = make_response(
                json.dumps("Token's user ID doesn't match given user ID."),
                401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the token is valid for the app
        if result['issued_to'] != CLIENT_ID:
            response = make_response(
                json.dumps("Token's client ID does not match the app's."), 401)
            print("Token's client ID does not match the app's.")
            response.headers['Content-Type'] = 'application/json'
            return response

        # Handle if a user is already logged in
        stored_token = login_session.get('access_token')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_token is not None and gplus_id == stored_gplus_id:
            response = make_response(
                json.dumps('Current user is already connected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Store access token in session for later use
        login_session['provider'] = 'google'
        login_session['access_token'] = credentials.access_token
        login_session['gplus_id'] = gplus_id

        # Make request to pull user info
        userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
        params = {'access_token': access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)
        data = answer.json()

        # Store user info
        login_session['username'] = data['name']
        login_session['picture'] = data['picture']
        login_session['email'] = data['email']
        # See if a user exists, if not, make a new one.
        # Then store user_id into the login_session
        user_id = getUserID(login_session['email'])
        if user_id is None:
            user_id = createUser(login_session)
        login_session['user_id'] = user_id

        return redirect(url_for('viewProfile'))


@app.route('/gdisconnect')
def gdisconnect():
    """Route for disconnecting Google+ user by requesting Google+ API to revoke
    the user's access_token from the session
    """

    access_token = login_session.get('access_token')

    # Only disconnect a connected user
    if access_token is None:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content/Type'] = 'application/json'
        return response

    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # Error
    if result['status'] != "200":
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400)
        )
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """Route for connecting Facebook user by going through OAuth flow,
    providing credentials and retrieving and storing user data sent back from
    from Facebook API
    """

    # Validate state key (protect against cross-site forgery attacks)
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # Obtain access_token for long-lived server token with GET method
        access_token = request.data
        # Pass client_secrets to verify server's identity
        app_id = json.loads(
            open('/var/www/html/qmenu/fb_client_secrets.json', 'r').read())['web']['app_id']
        app_secret = json.loads(
            open('/var/www/html/qmenu/fb_client_secrets.json', 'r').read())['web']['app_secret']
        url = ('https://graph.facebook.com/v2.9/oauth/access_token?grant_type'
               '=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_'
               'token=%s' % (app_id, app_secret, access_token))
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data = json.loads(result)

        # Extract access_token from response
        token = "access_token=" + data['access_token']

        # If token works, we can use it to make API calls with this new token
        # And store the call result data into data
        url = ('https://graph.facebook.com/v2.9/me?%s&fields=name,id,email'
               % token)
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data = json.loads(result)

        # Store data into our session
        login_session['provider'] = 'facebook'
        login_session['username'] = data["name"]
        login_session['email'] = data["email"]
        login_session['facebook_id'] = data["id"]

        # The token must be stored in the login_session to properly logout
        login_session['access_token'] = token

        # Facebook uses a separate API call to retrieve a profile picture
        url = ('https://graph.facebook.com/v2.9/me/picture?%s&redirect=0&'
               'height=200&width=200' % token)
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data = json.loads(result)

        # Store picture data into session
        login_session['picture'] = data["data"]["url"]

        # Check if user doesn't exist, store in database
        user_id = getUserID(login_session['email'])
        if user_id is None:
            user_id = createUser(login_session)
        login_session['user_id'] = user_id

        return redirect(url_for('viewProfile'))


@app.route('/fbdisconnect')
def fbdisconnect():
    """Route for disconnecting Google+ user by sending a delete request
    to Facebook in order to remove user's data and credentials from the session
    """

    facebook_id = login_session['facebook_id']

    # The access token must also be included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token=%s'
           % (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]


@app.route('/disconnect')
def disconnect():
    """Route to check provider and implement appropriate disconnecting function
    so that users can uniformly sign out of accounts regardless of whether
    they used Facebook or Google+ accounts
    """

    if 'provider' in login_session:
        # If user signed in with Google
        if login_session['provider'] == 'google':
            # Run Google disconnect function
            gdisconnect()
            # Clear Google-exclusive session data
            del login_session['access_token']
            del login_session['gplus_id']

        # If user signed in with Facebook
        if login_session['provider'] == 'facebook':
            # Run Facebook disconnect function
            fbdisconnect()
            # Clear Facebook-exclusive session data
            del login_session['facebook_id']

        # Then clear session data that was stored for either provider
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash('Successfully logged out. See you again soon!')
        return redirect(url_for('showRestaurants'))

    # Error if no data in session (user was not even logged in)
    else:
        response = make_response(
            json.dumps('Invalid request made.', 400)
        )
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/profile')
def viewProfile():
    """Page that shows a logged-in user's profile, logout option and his or her
    posted restaurants
    """

    # Confirm there is a user logged in
    if 'username' in login_session:
        # Pull current user and restaurants belonging to user
        current_user = getUserInfo(login_session['user_id'])
        restaurants = session.query(Restaurant).filter_by(
                    user_id=current_user.id).all()
        return render_template('profile.html', restaurants=restaurants)

    # Error if user is not logged in
    else:
        flash('Please log in to view your profile!')
        return redirect(url_for('showLogin'))


# =============
# API ENDPOINTS
# =============

@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    """Shows this apps' API endpoint for all menu items for a restaurant with
    the specific id
    """

    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    """Shows this apps' API endpoint for one menu item with the specific id"""

    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


# API Endpoint for all restaurants
@app.route('/restaurant/JSON')
def restaurantsJSON():
    """Shows this apps' API endpoint for all restaurants saved in the database
    """

    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


# ==============
# REGULAR ROUTES
# ==============

@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    """The homepage for this app that has a public template that prompts login
    and an exclusive template for logged in users to post a new restaurant.
    Associated with two different routes.
    """

    # Grab restaurants
    restaurants = session.query(Restaurant).order_by(Restaurant.name).all()

    # Show logged-in restaurant view
    if 'username' in login_session:
        return render_template('restaurants.html', restaurants=restaurants)

    # Show public restaurant view
    else:
        return render_template('publicrestaurants.html',
                               restaurants=restaurants)


@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    """Route that displays the form only for logged-in users to create a new
    restaurant to post onto the site
    """

    # Reroute if not logged in
    if 'username' not in login_session:
        flash('You have to be logged in to do that!')
        return redirect('/login')

    else:
        # POST
        if request.method == 'POST':
            newRestaurant = Restaurant(name=request.form['name'],
                                       user_id=login_session['user_id'])
            session.add(newRestaurant)
            flash('New restaurant, "%s", successfully created!'
                  % newRestaurant.name)
            session.commit()
            return redirect(url_for('showRestaurants'))
        # GET
        else:
            return render_template('newRestaurant.html')


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    """Route for logged-in users to edit the information of a restaurant only
    if this restaurant belongs to them
    """

    # Reroute if not logged in
    if 'username' not in login_session:
        flash('You have to be logged in to do that!')
        return redirect('/login')

    else:
        # Restaurant to edit
        editedRestaurant = session.query(Restaurant).filter_by(
            id=restaurant_id).one()

        # Confirm user is owner of restaurant
        current_user = getUserInfo(login_session['user_id'])
        if current_user.id == editedRestaurant.user_id:
            # POST
            if (request.method == 'POST' and request.form['name']):
                editedRestaurant.name = request.form['name']
                flash('Restaurant successfully edited to "%s"'
                      % editedRestaurant.name)
                return redirect(url_for('showRestaurants'))
            # GET
            else:
                return render_template('editRestaurant.html',
                                       restaurant=editedRestaurant)

        # Error if not owner of restaurant
        else:
            response = make_response(
                json.dumps('Malicious request detected. You are not authorized'
                           '. Your IP has been logged for security purposes.',
                           400))
            response.headers['Content-Type'] = 'application/json'
            return response


@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    """Route for logged-in users to delete a restaurant from the app only if
    this restaurant belongs to them
    """

    # Reroute if not logged in
    if 'username' not in login_session:
        flash('You have to be logged in to do that!')
        return redirect('/login')

    else:
        # Restaurant to delete
        restaurantToDelete = session.query(Restaurant).filter_by(
            id=restaurant_id).one()

        # Confirm user is owner of restaurant
        current_user = getUserInfo(login_session['user_id'])
        if current_user.id == restaurantToDelete.user_id:
            # POST
            if request.method == 'POST':
                session.delete(restaurantToDelete)
                flash('Restaurant, "%s", successfully deleted!'
                      % restaurantToDelete.name)
                session.commit()
                return redirect(url_for('showRestaurants',
                                        restaurant_id=restaurant_id))
            # GET
            else:
                return render_template('deleteRestaurant.html',
                                       restaurant=restaurantToDelete)

        # Error if not owner of restaurant
        else:
            response = make_response(
                json.dumps('Malicious request detected. You are not authorized'
                           '. Your IP has been logged for security purposes.',
                           400))
            response.headers['Content-Type'] = 'application/json'
            return response


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    """A restaurant's main page with list of menu items. Loads a public
    template or an exclusive template for logged in users to edit, add items
    or delete the restaurant. Associated with two different routes.
    """

    # Grab restaurant and menu items
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()

    # Show completely public menu
    if 'username' not in login_session:
        return render_template('publicmenu.html', items=items,
                               restaurant=restaurant)

    else:
        # Check current user
        current_user = getUserInfo(login_session['user_id'])
        # Show exclusive menu for users who own restaurant
        if current_user.id == restaurant.user_id:
            return render_template('menu.html', items=items,
                                   restaurant=restaurant)

        # Show public menu for users logged in but not owner
        else:
            return render_template('publicmenu.html', items=items,
                                   restaurant=restaurant,
                                   user=current_user)


@app.route('/restaurant/<int:restaurant_id>/menu/new/',
           methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    """Route that displays the form only for logged-in users to create a new
    menu item to post onto the specific restaurant
    """

    # Reroute if not logged in
    if 'username' not in login_session:
        flash('You have to be logged in to do that!')
        return redirect('/login')

    else:
        # Grab restaurant
        restaurant = session.query(Restaurant).filter_by(
            id=restaurant_id).one()

        # Confirm user is owner of restaurant
        current_user = getUserInfo(login_session['user_id'])
        if current_user.id == restaurant.user_id:
            # POST
            if request.method == 'POST':
                newItem = MenuItem(name=request.form['name'],
                                   description=request.form['description'],
                                   price=request.form['price'],
                                   course=request.form['course'],
                                   restaurant_id=restaurant_id,
                                   user_id=login_session['user_id'])
                session.add(newItem)
                session.commit()
                flash('New menu item, "%s", successfully created!'
                      % newItem.name)
                return redirect(url_for('showMenu',
                                        restaurant_id=restaurant_id))
            # GET
            else:
                return render_template('newmenuitem.html',
                                       restaurant_id=restaurant_id)

        # Error if not owner of restaurant
        else:
            response = make_response(
                json.dumps('Malicious request detected. You are not authorized'
                           '. Your IP has been logged for security purposes.',
                           400))
            response.headers['Content-Type'] = 'application/json'
            return response


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    """Route for logged-in users to edit the information of a menu item only
    if the specific restaurant belongs to them
    """

    # Reroute if not logged in
    if 'username' not in login_session:
        flash('You have to be logged in to do that!')
        return redirect('/login')

    else:
        # Grab edit item and its restaurant
        editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
        restaurant = session.query(Restaurant).filter_by(
            id=restaurant_id).one()

        # Confirm user is owner of restaurant
        current_user = getUserInfo(login_session['user_id'])
        if current_user.id == restaurant.user_id:
            # POST
            if request.method == 'POST':
                if request.form['name']:
                    editedItem.name = request.form['name']
                if request.form['description']:
                    editedItem.description = request.form['description']
                if request.form['price']:
                    editedItem.price = request.form['price']
                if request.form['course']:
                    editedItem.course = request.form['course']

                session.add(editedItem)
                session.commit()
                flash('Menu item successfully edited!')
                return redirect(url_for('showMenu',
                                        restaurant_id=restaurant_id))

            # GET
            else:
                return render_template('editmenuitem.html',
                                       restaurant_id=restaurant_id,
                                       menu_id=menu_id,
                                       item=editedItem)

        # Error if not owner of restaurant
        else:
            response = make_response(
                json.dumps('Malicious request detected. You are not authorized'
                           '. Your IP has been logged for security purposes.',
                           400))
            response.headers['Content-Type'] = 'application/json'
            return response


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    """Route for logged-in users to delete a menu item only if the specific
    restaurant belongs to them
    """

    # Reroute if not logged in
    if 'username' not in login_session:
        flash('You have to be logged in to delete a menu item.')
        return redirect('/login')

    else:
        # Grab restaurant and item to delete
        restaurant = session.query(Restaurant).filter_by(
            id=restaurant_id).one()
        itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()

        # Confirm user is owner of restaurant
        current_user = getUserInfo(login_session['user_id'])

        if current_user.id == restaurant.user_id:
            # POST
            if request.method == 'POST':
                session.delete(itemToDelete)
                session.commit()
                flash('Menu item successfully deleted!')
                return redirect(url_for('showMenu',
                                        restaurant_id=restaurant_id))

            # GET
            else:
                return render_template('deleteMenuItem.html',
                                       item=itemToDelete)

        # Error if not owner of restaurant
        else:
            response = make_response(
                json.dumps('Malicious request detected. You are not authorized'
                           '. Your IP has been logged for security purposes.',
                           400))
            response.headers['Content-Type'] = 'application/json'
            return response


# Server configuration
if __name__ == '__main__':
    app.secret_key = 'shhhhhh-secret'
    app.debug = True
    app.run()
