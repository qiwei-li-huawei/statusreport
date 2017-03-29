import functools
import datetime

from flask import Flask, redirect, url_for, session, jsonify, current_app, make_response
from flask_oauth import OAuth

from flask_login import login_user, logout_user, login_required, current_user
from flask_principal import Identity, AnonymousIdentity, identity_changed

from app import app
import models
import utils
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
    return "hello_world"

def _get_current_user():
    user = models.User.objects.get(username=current_user.username)
    return user


@app.route('/login/google')
def login_google():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)


def authorized():
    resp = google.authorized_response()
    if resp is None:
        return redirect(url_for('accounts.login'))
    session['google_token'] = (resp['access_token'], '')
    user_info = google.get('userinfo')
    try:
        user = models.User.objects.get(email=user_info.data['email'])
    except models.User.DoesNotExist:
        user = None

    if user is None:
        return redirect(url_for('register'))

    login_user(user)
    user.last_login = datetime.datetime.now
    user.save()
    identity_changed.send(current_app._get_current_object(), identity=Identity(user.username))
    return redirect(request.args.get('next') or url_for('index'))


@google.tokengetter
def get_access_token():
    return session.get('access_token')


@app.route('/api/login', methods=['POST'])
def login():
    data = utils.get_request_data()
    try:
        user = models.User.objects.get(username=data.username)
    except models.User.DoesNotExist:
        user = None

    if not user or not user.verify_password(data.password):
        raise exception_handler.Unauthorized()

    login_user(user, data.remember_me)
    user.last_login = datetime.datetime.now
    user.save()
    identity_changed.send(current_app._get_current_object(), identity=Identity(user.username))
    return utils.make_json_response(
        200,
        user.to_dict()
        )

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    user = _get_current_user()
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
    
    try:
        exist_user1 = models.User.objects.get(username=data.username)
    except models.User.DoesNotExist:
        exist_user1 = None

    try:
        exist_user2 = models.User.objects.get(username=data.email)
    except models.User.DoesNotExist:
        exist_user2 = None

    if exist_user1 is not None or exist_user2 is not None:
        raise exception_handler.BadRequest("user already exist")
    
    user = models.User()
    user.username = data['username']
    user.email = data['email']
    user.save()

    return utils.make_json_response(
        200,
        user.to_dict()
        )

@app.route('/api/tasks', methods=['GET'])
@login_required
def list_tasks():
    tasks = models.Task.objects.order_by('-due_time')

    cur_status = request.args.get('status')
    if cur_status:
        tasks = tasks.filter(status=cur_status)

    tasks_dict = {}
    for task in tasks:
        tasks_dict.update(task.to_dict())

    return utils.make_json_response(
        200,
        tasks_dict
        )

@app.route('/api/tasks/<string:tasktitle>', methods=['GET'])
@login_required
def get_task(tasktitle):
    task = models.Task.objects.get(title=tasktitle)

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
        task.assignee.append(models.User.objects.get(username=data['assign']))
    task.status = data['status']
    task.tags = data['tags']
    task.due_time = data['due_time']
    task.set_task_date(datetime.now(), datetime.now())
    if task.pub_time < task.due_time:
        task.save()
        return utils.make_json_response(
            200,
            data
            )
    else:
        raise exception_handler.BadRequest(
            'due time %s is earlier than pub time %s' % (
                    data['due_time'], datetime.now()
                )
            )

@app.route('/api/tasks/<string:tasktitle>', methods=['PUT'])
@login_required
def update_task(tasktitle):
    data = utils.get_request_data()

    task = models.Task.objects.get(title=tasktitle)
    if data['title']:
        task.title = data['title']
    if data['content']:
        task.content = data['content']
    if data['status']:
        if data['status'] in ['todo', 'ongoing'] and datetime.now() > task.due_time:
            raise exception_handler.BadRequest(
                'due time %s already passed' % data['due_time']
                )
        if data['status'] == 'overdue' and datetime.now() < task.due_time:
            left_days, left_hours, left_minutes = utils.shifttimedelta(timedelta(data['due_time'] - datetime.now()))
            raise exception_handler.BadRequest(
                'still %s days %s hours %s minutes left' % (
                        left_days, left_hours, left_minutes
                    )
                )
    if data['tags']:
        task.tags = data['tags']
    task.update_time = datetime.now()
    task.save()
    return utils.make_json_response(
        200,
        task.to_dict()
        )



@app.route('/api/tasks/<string:username>', methods=['GET'])
@login_required
def get_user_tasks(username):
    tasks = models.Task.objects.all()

    cur_status = request.args.get('status')
    if cur_status:
        tasks = tasks.filter(status=cur_status)

    user_task_dict = []
    for task in tasks:
        if username in [user.username for user in task.assignee] or username == task.manager.username:
            user_task_dict.update(task.to_dict())

    return utils.make_json_response(
        200,
        user_task_dict
        )


@app.route('/api/users', methods=['GET'])
@login_required
def get_all_users():
    users = models.User.objects
    output = []
    for user in users:
        output.append(user.to_dict())
    return utils.make_json_response(
        200,
        output
        )

@app.route('/api/users/<string:username>', methods=['GET'])
@login_required
def get_user(username):
    user = models.User.objects.get(username=username)
    if user is None:
        raise exception_handler.ItemNotFound("user not found")
    return utils.make_json_response(
        200,
        user.to_dict()
        )


'''
def login_required(func):
    @functools.wraps(func)
    def decorated_api(*args, **kwargs):
        get_access_token()
        access_token = session.get('access_token')
        if access_token is None:
            return redirect(url_for('login'))

        from urllib2 import Request, urlopen, URLError
        headers = {'Authorization': 'OAuth '+ access_token}
        req = Request('https://www.googleapis.com/oauth2/v1/userinfo?alt=json',
              None, headers)

        try:
            res = urlopen(req)
        except URLError, e:
            if e.code == 401:
                session.pop('access_token', None)
                return redirect(url_for('login'))
            return redirect(url_for('login'))
        current_user_email = res.read().get('email')
        current_user = models.User.objects.get(email=current_user_email)
        if current_user is None:
            redirect(url_for('register', user_email=current_user_email))
        return func(*args, **kwargs)
    return decorated_api
'''

'''
@app.route('/')
def index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))

    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError

    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('login'))
        return res.read()

    return res.read()
'''
if __name__ == '__main__':
    app.run()