import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#Nothing to see here, move along #######################################################################################

secret = 'ROFLcoptor'

# Base Blog Handler Helpers ############################################################################################

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Base Blog Handler ####################################################################################################

class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# Function for the structuring of posts when rendering##################################################################


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
    response.out.write(post.name)
    response.out.write(post.id)

########################################################################################################################

class MainPage(BlogHandler):
    def get(self):
        self.redirect('/blog')

# Functions used for login username and password ########################################################################


def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# Model for the User table in Gql. Stores name, pw_hash, email##########################################################

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Defines the contents of a post: subject, content, created, last_modified, and author##################################

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

#Handler for blog homepage##############################################################################################

class BlogFront(BlogHandler):

    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc")
        self.render('front.html', posts = posts)

# Handler for retrieving a post#########################################################################################

class PostPage(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

# Handler for registering a new post####################################################################################


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')
        likes = 0


        ### THIS IS THE SECTION OF THE FUNCTION THAT ACTUALLY ADDS THE POST TO THE GQL LIBRARY ###
        ### THIS IS THE GQL ###
        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = author, likes = 0)
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


########################################## Handler for registering a new user ##########################################

class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

########################################## Handler for registering a new user ##########################################

class Register(Signup):

    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

############################################# Handler for login requests ###############################################

class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/login/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

########################################### Handler for logging out a signed in user ###################################

class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/signup')

# Handler to welcome user after signing in. Doubles as profile page#####################################################

class Welcome(BlogHandler):

    def get(self):
        username = self.request.get('username')
        if self.user:
            self.render('welcome.html', username = username)
        else:
            self.redirect('/signup')

# Handler to view your own posts under the profile section##############################################################

class MyPosts(BlogHandler):

    def get(self):
        username = self.user.name
        posts = db.GqlQuery("SELECT * FROM Post where author = :author", author=username)
        self.render('myposts.html', username = self.user.name, posts = posts)

# Handler for deleting a post###########################################################################################

class DeletePost(BlogHandler):

    def get(self, post):
        self.render('deletepost.html')

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        db.delete(key)
        self.redirect('/')


# Handler for liking a post ############################################################################################

class LikePost(BlogHandler):
    #def get(self, blog):
     #   self.render('likes.html')

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        post.likes += 1
        post.put()
        self.redirect("/blog")





#WSGI Mapping ##########################################################################################################

app = webapp2.WSGIApplication  ([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/post/([0-9]+)', PostPage),
                               ('/post/([0-9]+)/deletepost', DeletePost),
                               ('/post/([0-9]+)/likes', LikePost),
                               ('/post/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/welcome/myposts', MyPosts),
                               ('/login/welcome', MyPosts),
                               ],
                              debug=True)


