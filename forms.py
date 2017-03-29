#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask_mongoengine.wtf import model_form
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, HiddenField, RadioField, FileField, IntegerField
from wtforms import widgets, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo, URL, Optional

from . import models

class UserForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,128), Email()])
    role = SelectField('Role', choices=models.ROLES)

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[Required()])
    abstract = TextAreaField('Abstract')
    tags_str = StringField('Tags')

class CommentForm(FlaskForm):
    email = StringField('* Email', validators=[Required(), Length(1,128), Email()])
    author = StringField('* Name', validators=[Required(), Length(1,128)])
    content = TextAreaField('* Comment <small><span class="label label-info">markdown</span></small>', validators=[Required()])
    comment_id = HiddenField('comment_id')
