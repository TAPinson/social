import os
import re
import random
import hashlib
import hmac
from string import letters
import time
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Nothing to see here, move along #############################################

secret = 'ROFLcoptor'

# Base Blog Handler Helpers ##################################################


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Base Blog Handler ##########################################################


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

# Function for redirecting to /blog###########################################


class MainPage(BlogHandler):
    def get(self):
        self.redirect('/blog')
        return


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
    response.out.write(post.name)
    response.out.write(post.id)


def render_comment(response, comment):
    response.out.write(comment.author)
    response.out.write(comment.comment)
    response.out.write(comment.post)

# Functions used for login username and password #############################


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)

# Model for the User table in Gql. Stores name, pw_hash, email################


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Defines the contents of a post #############################################


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)
    likers = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))

# Handler for blog homepage ###################################################


class BlogFront(BlogHandler):

    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc")
        self.render('front.html', posts=posts)

# Handler for retrieving a post ##############################################


class PostPage(BlogHandler):

    def get(self, post_id):
        p = self
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post)

# Handler for registering a new post##########################################


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")
            return

    def post(self):
        if not self.user:
            self.redirect('/blog')
            return
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')
        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     author=author, likes=0, likers="none")
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
            return
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Handler for registering a new user #########################################


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        params = dict(username=self.username,
                      email=self.email)
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

# Handler for registering a new user #########################################


class Register(Signup):

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/blog')

# Handler for login requests #################################################


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
            return
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


# Handler for logging out a signed in user ###################################


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/signup')

# Handler to welcome user after signing in. Doubles as profile page###########


class Welcome(BlogHandler):

    def get(self):
        username = self.request.get('username')
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

# Handler to view your own posts under the profile section####################


class MyPosts(BlogHandler):

    def get(self):
        username = self.user.name
        posts = db.GqlQuery("SELECT * FROM Post where author = :author",
                            author=username)
        self.render('myposts.html', username=username, posts=posts)

# Handler for deleting a post#################################################


class DeletePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
            return
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post is not None:
                if self.user.name == post.author:
                    self.render('deletepost.html')
                else:
                    self.render('error.html')

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
            return
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post and self.user.name == post.author:
                if self.user.name == post.author:
                    db.delete(key)
                    time.sleep(0.1)
                    self.redirect('/blog')
                    return
                else:
                    self.render('error.html')
            else:
                self.render('error.html')

# Handler for liking a post ##################################################


class LikePost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect('/login')
            return
        else:
            if post is None:
                self.render('error.html')
            else:
                liker = self.user.name
                if liker != post.author:
                    if liker not in post.likers:
                        post.likes += 1
                        post.likers = post.likers + " " + liker
                        post.put()
                        time.sleep(0.1)
                        self.redirect("/blog")
                        return
                    elif liker in post.likers:
                        names = post.likers
                        print names
                        names = names.split()
                        print names
                        if liker in names:
                            print names
                            names.remove(liker)
                            print names
                            post.likes -= 1
                            names = "".join(names)
                            post.likers = names
                            post.put()
                            time.sleep(0.1)
                            self.redirect("/blog")
                            return
                else:
                    self.render("error.html")

# Handler for Commenting on a post ###########################################


class Comment(db.Model):
    post = db.StringProperty(required=True)
    comment = db.StringProperty(required=True)
    author = db.StringProperty(required=True)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))


class NewComment(BlogHandler):

    def get(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not self.user:
            self.redirect('/logn')
            return
        else:
            if post is not None:
                subject = post.subject
                content = post.content
                self.render('comment.html', subject=subject, post=post,
                            content=content, postuser=post.author, pkey=post.key())
            else:
                self.render('error.html')
                return

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        if not self.user:
            self.redirect('/login')
            return
        else:
            author = self.user.name
            comment = db.GqlQuery("SELECT * FROM Comment WHERE post= :post and"
                                  " author= :author", post=post_id, author=author)
            if comment is not None:
                post = db.get(key)
                print post
                if post is not None:
                    comment = self.request.get('comment')
                    author = self.user.name
                    if comment:
                        parent = self.user.key()
                        c = Comment(post=post_id, comment=comment, parent=parent,
                            author=author)
                        c.put()
                        p = post
                        self.redirect(('/post/%s' % str(p.key().id()) + ('/comment')))
                        return
                    else:
                        self.render('error.html')
            else:
                self.render('error.html')

# Handler for deleting a comment #############################################


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if not self.user:
            self.render('error.html')
        else:
            comment = Comment.get_by_id(int(comment_id),
                                        parent=self.user.key())
            if comment is not None:
                if self.user.name == comment.author:
                    db.delete(comment)
                    time.sleep(0.1)
                    self.redirect('/blog')
                    return
                else:
                    self.render('error.html')
            else:
                self.render('error.html')

# Handler for editing a post #################################################


class EditPost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect("/login")
            return
        else:
            post = Post.get_by_id(int(post_id), parent=blog_key())
            if post is not None:
                if self.user.name == post.author:
                    content = Post.content
                    subject = Post.subject
                    self.render("editpost.html",
                                content=content,
                                post_id=post_id,
                                subject=subject, post=post)
                else:
                    self.render('error.html')
            else:
                self.render('error.html')

    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if post is not None:
            if not self.user:
                self.redirect('/login')
            else:
                if self.user.name != post.author:
                    self.render("error.html")
                else:
                    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                    p = db.get(key)
                    p.content = self.request.get('content')
                    p.put()
                    time.sleep(0.1)
                    self.redirect(('/post/%s' % str(p.key().id()) + ('/editpost')))
                    return
        else:
            self.render('error.html')

# Handler for editing a comment ##############################################


class EditComment(BlogHandler):

    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(comment_id), parent=blog_key())
        comments = Comment.get_by_id(int(comment_id),
                                     parent=self.user.key())
        if comments is not None:
            content = comments.comment
            if not self.user:
                self.render('error.html')
            else:
                author = self.user.name
                commentToEdit = comments.comment
                commentToEdit = self.request.get('commentToEdit')
                content = Post.content
                subject = Post.subject
                self.render('editcomment.html', subject=subject, post=post,
                            content=content, comments=comments)
        else:
            self.render('error.html')

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect("/login")
            return
        else:
            comments = Comment.get_by_id(int(comment_id),
                                         parent=self.user.key())
            if comments:
                if comments.author == self.user.name:
                    commentToEdit = comments.comment
                    comment = self.request.get('comment')
                    comments.comment = comment
                    comments.put()
                    self.redirect(('/post/%s' % str(post_id) + ('/comment')))
                    return
                else:
                    self.render('error.html')
            else:
                self.render('error.html')

# Handler for viewing a comment ###############################################


class ViewComment(BlogHandler):

    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comments = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if post is not None:
            if comments is not None:
                self.render('viewcomment.html', post=post,
                    comments=comments, comment_id=comment_id)
            else:
                self.render('error.html')
        else:
            self.render('error.html')

# Fix for data not persisting in development environment datastore ############

developmentServer = False

if os.environ.get('SERVER_SOFTWARE','').startswith('Development'):
    developmentServer = True

class BaseRequestHandler(webapp2.RequestHandler):
    def dispatch(self):
        retValue = super(BaseRequestHandler, self).dispatch()
        if developmentServer:
                from google.appengine.tools import dev_appserver
                dev_appserver.TearDownStubs()

        return retValue


# WSGI Mapping ################################################################

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/post/([0-9]+)', PostPage),
                               ('/post/([0-9]+)/comment', NewComment),
                               ('/post/([0-9]+)/comment/([0-9]+)',
                                ViewComment),
                               ('/post/([0-9]+)/deletepost', DeletePost),
                               ('/post/([0-9]+)/comment/([0-9]+)/'
                                'deletecomment', DeleteComment),
                               ('/post/([0-9]+)/likes', LikePost),
                               ('/post/([0-9]+)/editpost', EditPost),
                               ('/post/([0-9]+)/comment/([0-9]+)/editcomment',
                                EditComment),
                               ('/post/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/welcome/myposts', MyPosts),
                               ], debug=True)
