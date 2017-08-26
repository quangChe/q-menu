# QMenu

A fully functional restaurant web application for users to register their Facebook or Google+ accounts in order to post restaurants and menu items.


## Features:

1. Stores data for restaurants, restaurants' menu items and user profiles using PostgreSQL database
2. Database CRUD operations and schema configured using the SQLAlchemy ORM
3. Implements OAuth2 protocol with Facebook and Google+ API for fast and reliable registration and sign in
4. Currently runs locally, using Vagrant. All necessary libraries are included on **pg_config.sh** and will be installed upon setting up Vagrant


## Tools Required:

* PostgreSQL v9.5
* Flask v0.12.2
* Flask-Login v0.1.3
* SQLAlchemy v1.0.11
* Psycopg2 v2.6.1
* Oauth2client v4.1.2
* Requests v2.18.4
* Httplib2 v0.10.3


## How To Run Application:

The application requires credentials from Google and Facebook for OAuth2 authentication:

1. Create a Google API project to acquire the client ID and secret for your *client_secrets.json* file. More instructions on that [here.](https://developers.google.com/identity/sign-in/web/devconsole-project)
2. Create a Facebook API application to acquire the app ID and app secret for your *fb_client_secrets.json* file. More instructions on that [here.](https://developers.facebook.com/docs/apps/register)

### Server configurations

To run the application, a server or virtual environment is required to host the application publicly or locally. Currently, it is being served on a Ubuntu web server hosted by Amazon Lightsail. Further details on the server's configurations can be found [here.](https://github.com/quangChe/ubuntu-web-server/blob/master/README.md)

#### View the live application [here.](http://52.40.185.170/)
