# -*- coding: utf-8 -*-
"""
    MiniTwit
    ~~~~~~~~
    A microblogging application written with Flask and sqlite3.
    :copyright: (c) 2015 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""

import time
from sqlite3 import dbapi2 as sqlite3
import uuid
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack
from werkzeug import check_password_hash, generate_password_hash

sqlite3.register_converter('GUID', lambda b: uuid.UUID(bytes_le=b))
sqlite3.register_adapter(uuid.UUID, lambda u: buffer(u.bytes_le))

# configuration
DATABASE = '/tmp/minitwit.db'
DATABASE0 = '/tmp/minitwit0.db'
DATABASE1 = '/tmp/minitwit1.db'
DATABASE2 = '/tmp/minitwit2.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = 'development key'

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)

def calculate_shard(userId):
    """Calcs 0 based shard based on # of DBs (3)"""
    return userId.int % 3

def get_db(shardKey):
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top

    if shardKey == 0:
        if not hasattr(top, 'sqlite_db0'):
            top.sqlite_db0 = sqlite3.connect(DATABASE0, detect_types=sqlite3.PARSE_DECLTYPES)
            top.sqlite_db0.row_factory = sqlite3.Row
        return top.sqlite_db0

    elif shardKey == 1:
        if not hasattr(top, 'sqlite_db1'):
            top.sqlite_db1 = sqlite3.connect(DATABASE1, detect_types=sqlite3.PARSE_DECLTYPES)
            top.sqlite_db1.row_factory = sqlite3.Row
        return top.sqlite_db1

    if not hasattr(top, 'sqlite_db2'):
        top.sqlite_db2 = sqlite3.connect(DATABASE2, detect_types=sqlite3.PARSE_DECLTYPES)
        top.sqlite_db2.row_factory = sqlite3.Row
    return top.sqlite_db2

def get_all_dbs():
    """Opens new database connections if there are none yet for the
    current application context and returns list of all db connections
    """
    top = _app_ctx_stack.top

    if not hasattr(top, 'sqlite_db0'):
        top.sqlite_db0 = sqlite3.connect(DATABASE0, detect_types=sqlite3.PARSE_DECLTYPES)
        top.sqlite_db0.row_factory = sqlite3.Row
    if not hasattr(top, 'sqlite_db1'):
        top.sqlite_db1 = sqlite3.connect(DATABASE1, detect_types=sqlite3.PARSE_DECLTYPES)
        top.sqlite_db1.row_factory = sqlite3.Row
    if not hasattr(top, 'sqlite_db2'):
        top.sqlite_db2 = sqlite3.connect(DATABASE2, detect_types=sqlite3.PARSE_DECLTYPES)
        top.sqlite_db2.row_factory = sqlite3.Row
    return list([top.sqlite_db0,top.sqlite_db1,top.sqlite_db2])


@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db0'):
        top.sqlite_db0.close()
    if hasattr(top, 'sqlite_db1'):
        top.sqlite_db1.close()
    if hasattr(top, 'sqlite_db2'):
        top.sqlite_db2.close()


def init_db():
    """Initializes the database."""
    dbs = get_all_dbs()
    for db in dbs:
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
            db.commit()


@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')

def query_db_shard(query, shard, args=(), one=False):
    cur = get_db(shard).execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    dbs = get_all_dbs()
    for db in dbs:
        cur = db.execute('select user_id from user where username = ?',
                  [username])
        rv = cur.fetchall()
        if rv:
            return rv[0]['user_id']
    return None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        shard = calculate_shard(session['user_id'])
        g.user = query_db_shard('select * from user where user_id = ?',
                                shard, [session['user_id']], one=True)


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    messages = []

    dbs = get_all_dbs()
    shard = calculate_shard(session['user_id'])
    rowIds = query_db_shard('''
    select whom_id from follower where who_id = ?''',
    shard, [session['user_id']])
    # Grab our own tweets
    follower_ids = []
    for id in rowIds:
        follower_ids.append(id['whom_id'])
    follower_ids.append(session['user_id'])
    query = 'select message.*, user.* from message, user        \
    where message.author_id = user.user_id and                  \
    user.user_id in ('+','.join(['?']*len(follower_ids))+')     \
    order by message.pub_date desc limit (?)'
    # Include per page arguement
    follower_ids.append(PER_PAGE)
    for db in dbs:
        res = db.execute(query,follower_ids)
        messages += res.fetchall()

    # Not sure which order they should be sorted in (how twitter/minitwit
    # does it, but this should be fine?)
    # Also cuts off additional rows. (Had to pull PER_PAGE per DB because
    # of that whole pidgeonhole theory thing yo)
    if messages:
        messages.sort(key=lambda x: x['pub_date'])
        messages = messages[:30]
    return render_template('timeline.html', messages=messages)


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    messages = []
    dbs = get_all_dbs()
    for db in dbs:
        res = db.execute('''
            select message.*, user.* from message, user
            where message.author_id = user.user_id
            order by message.pub_date desc limit ?''', [PER_PAGE])
        messages += res.fetchall()
    if messages:
        messages.sort(key=lambda x: x['pub_date'])
        messages = messages[:30]
    return render_template('timeline.html', messages=messages)


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    profile_user_id = get_user_id(username)
    print profile_user_id
    if profile_user_id is None:
        abort(404)
    shard = calculate_shard(profile_user_id)
    profile_user = query_db_shard('select * from user where user_id = ?', shard,
                            [profile_user_id], one=True)
    followed = False
    if g.user:
        user_shard = calculate_shard(session['user_id'])
        print user_shard
        print profile_user
        followed = query_db_shard('''select 1 from follower where
            follower.who_id = ? and follower.whom_id = ?''', user_shard,
            [session['user_id'], profile_user['user_id']],
            one=True) is not None
    return render_template('timeline.html', messages=query_db_shard('''
            select message.*, user.* from message, user where
            user.user_id = message.author_id and user.user_id = ?
            order by message.pub_date desc limit ?''', shard,
            [profile_user['user_id'], PER_PAGE]), followed=followed,
            profile_user=profile_user)


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    shard = calculate_shard(session['user_id'])
    db = get_db(shard)
    db.execute('insert into follower (who_id, whom_id) values (?, ?)',
              [session['user_id'], whom_id])
    db.commit()
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    shard = calculate_shard(session['user_id'])
    db = get_db(shard)
    db.execute('delete from follower where who_id=? and whom_id=?',
              [session['user_id'], whom_id])
    db.commit()
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        shard = calculate_shard(session['user_id'])
        db = get_db(shard)
        db.execute('''insert into message (message_id, author_id, text, pub_date)
          values (?, ?, ?, ?)''', (uuid.uuid4(), session['user_id'], request.form['text'],
                                int(time.time())))
        db.commit()
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        dbs = get_all_dbs()
        user = None
        for db in dbs:
            row = db.execute('''select * from user where
            username = ?''', [request.form['username']])
            user = row.fetchone()
            if user is not None:
                break
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    """need to handle get user id and make sure username is distinct across db"""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            userID = uuid.uuid4()
            shard = calculate_shard(userID)
            db = get_db(shard)
            db.execute('''insert into user (
              user_id, username, email, pw_hash) values (?, ?, ?, ?)''',
              [userID, request.form['username'], request.form['email'],
               generate_password_hash(request.form['password'])])
            db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url
