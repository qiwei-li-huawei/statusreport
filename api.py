import functools
import simplejson as json
import ast
from datetime import datetime

from flask import Flask, redirect, url_for, session, jsonify, current_app, make_response
from flask_oauth import OAuth

from flask_login import login_user, logout_user, login_required, current_user
from flask_principal import Identity, AnonymousIdentity, identity_changed

from app import app
import models
import utils
import exception_handler
from config import *

oauth = OAuth()

google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)

@app.route('/', methods=['GET'])
def hello_world():
    user = current_user
    print(user)
    print(models.User.objects.get(username="qiwei.li"))
    print(datetime.datetime.now())
    return "hello_world"

def _get_current_user():
    user = models.User.objects.get(username=current_user.username)
    return user

def _get_request_args(**kwargs):
    args = dict(request.args)
    for key, value in args.items():
        if key in kwargs:
            converter = kwargs[key]
            if isinstance(value, list):
                args[key] = [converter(item) for item in value]
            else:
                args[key] = converter(value)
    return args

@app.route('/login/google')
def login_google():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)


@app.route('/authorized')
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']

    ### login with google failed
    if access_token is None:
        raise exception_handler.Unauthorized("failed login with google, please retry")
        #return redirect(url_for('/login'))

    session['access_token'] = access_token, ''
    
    from urllib2 import Request, urlopen, URLError

    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo?alt=json', None, headers)

    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            session.pop('access_token', None)
            return redirect(url_for('login'))
        return redirect(url_for('login'))


    current_user_email = json.loads(str(res.read()))["email"]
    google_user = models.User.objects.get(email=current_user_email)
    if google_user is None:
        raise exception_handler.Unauthorized("user not exist, please register")
        #redirect(url_for('register'))

    login_user(google_user, True, True)
    google_user.last_login = datetime.datetime.now()
    google_user.save()

    identity_changed.send(current_app._get_current_object(), identity=Identity(google_user.username))
    return utils.make_json_response(
        200,
        google_user.to_dict()
        )

@google.tokengetter
def get_access_token():
    return session.get('access_token')


@app.route('/api/login', methods=['POST'])
def login():
    data = utils.get_request_data()
    try:
        user = models.User.objects.get(username=data["username"])
    except models.User.DoesNotExist:
        user = None

    if not user or not user.verify_password(data["password"]):
        raise exception_handler.Unauthorized("username or password does not match")

    success = login_user(user, data["remember_me"], True)
    user.last_login = datetime.datetime.now()
    user.save()

    identity_changed.send(current_app._get_current_object(), identity=Identity(user.username))
    return utils.make_json_response(
        200,
        user.to_dict()
        )


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    user = models.User.objects.get(username=current_user.username)

    logout_user()

    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)
    
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    return utils.make_json_response(
        200,
        user.to_dict()
        )


@app.route('/api/register', methods=['POST'])
def register():
    data = utils.get_request_data()

    if (models.User.objects.filter(username=data["username"]).count() > 0 or 
    models.User.objects.filter(email=data["email"]).count() > 0):
        raise exception_handler.BadRequest("user already exist")
    
    user = models.User()
    user.username = data['username']
    user.email = data['email']
    user.password = data['password']
    user.save()

    return utils.make_json_response(
        200,
        user.to_dict()
        )

@app.route('/api/listtasks/<string:status>', methods=['GET'])
@login_required
def list_tasks(status):
    if status == "all":
        tasks = models.Task.objects.order_by('-due_time')
    else:
        tasks = models.Task.objects.filter(status=status)

    tasks_dict = {}
    for task in tasks:
        tasks_dict.update({task.title: task.to_dict()})

    return utils.make_json_response(
        200,
        tasks_dict
        )


@app.route('/api/tasks/<string:tasktitle>', methods=['GET'])
@login_required
def get_task(tasktitle):
    try:
        task = models.Task.objects.get(title=tasktitle)
    except models.Task.DoesNotExist:
        raise exception_handler.ItemNotFound(
            "task %s not exist" % tasktitle
            )
    return utils.make_json_response(
        200,
        task.to_dict()
        )

@app.route('/api/tasks', methods=['POST'])
@login_required
def create_task():
    data = utils.get_request_data()

    task = models.Task()

    task.title = data['title']
    task.content = data['content']
    task.manager = models.User.objects.get(username=data['manager'])

    for assign in data['assignee']:
        task.assignee.append(models.User.objects.get(username=assign))

    task.status = data['status']
    task.tags = data['tags']
    task.due_time = datetime.datetime.strptime(data['due_time'], '%b %d %Y %I:%M%p')
    task.pub_time = datetime.datetime.now()
    task.update_time = datetime.datetime.now()

    if task.pub_time < task.due_time:
        task.save()
        return utils.make_json_response(
            200,
            task.to_dict()
            )
    else:
        raise exception_handler.BadRequest(
            'due time %s is earlier than pub time %s' % (
                    data['due_time'], datetime.datetime.now()
                )
            )

@app.route('/api/tasks/<string:tasktitle>', methods=['PUT'])
@login_required
def update_task(tasktitle):
    data = utils.get_request_data()

    try:
        task = models.Task.objects.get(title=tasktitle)
    except models.Task.DoesNotExist:
        raise exception_handler.BadRequest(
            'task %s not exist' % tasktitle
            )
    print(data['content'])
    if data.get('title'):
        print(task.content)
        task.title = data['title']

    if data.get('content'):
        task.content = data['content']
    if data.get('status') and data['status'] in ['todo', 'ongoing'] and datetime.datetime.now() > task.due_time:
        raise exception_handler.BadRequest(
            'due time %s already passed' % task.due_time
            )
    if data.get('status') and data['status'] == 'overdue' and datetime.datetime.now() < task.due_time:
        left_days, left_hours, left_minutes = utils.shifttimedelta(task.due_time - datetime.datetime.now())
        raise exception_handler.BadRequest(
            'still %s days %s hours %s minutes left' % (
                    left_days, left_hours, left_minutes
                )
            )
    if data.get('status'):
        task.status = data['status']
    if data.get('tags'):
        task.tags = data['tags']
    if data.get('due_time'):
        task.due_time = datetime.datetime.strptime(data['due_time'], '%b %d %Y %I:%M%p')
    task.update_time = datetime.datetime.now()
    task.save()
    return utils.make_json_response(
        200,
        task.to_dict()
        )


@app.route('/api/usertasks/<string:username>/<string:status>', methods=['GET'])
@login_required
def get_user_tasks(username, status):
    if status == "all":
        tasks = models.Task.objects.order_by('-due_time')
    else:
        tasks = models.Task.objects.filter(status=status).order_by('-due_time')

    user_task_dict = {}
    for task in tasks:
        if username in [user.username for user in task.assignee] or username == task.manager.username:
            user_task_dict.update({task.title: task.to_dict()})

    return utils.make_json_response(
        200,
        user_task_dict
        )


@app.route('/api/users', methods=['GET'])
@login_required
def get_all_users():
    users = models.User.objects.all()
    users_dict = {}
    for user in users:
        users_dict.update({user.username: user.to_dict()})
    return utils.make_json_response(
        200,
        users_dict
        )


@app.route('/api/users/<string:username>', methods=['GET'])
@login_required
def get_user(username):
    try:
        user = models.User.objects.get(username=username)
    except models.User.DoesNotExist:
        raise exception_handler.BadRequest(
            "user %s not exist" % username
            )

    return utils.make_json_response(
        200,
        user.to_dict()
        )


if __name__ == '__main__':
    app.run()