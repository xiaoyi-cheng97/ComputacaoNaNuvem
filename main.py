
import os
import time

import pandas as pd

from flask import (
    Flask, abort, request, redirect, url_for, render_template, g,
    send_from_directory)

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql.expression import func
from PIL import Image, ImageDraw, ImageFont
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_login import UserMixin
from datetime import datetime
from flask_login import login_user, current_user, logout_user, login_required
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from sqlalchemy.orm import relationship
from google.cloud import storage
from pyspark.sql.types import *
import pyspark
from pyspark.sql import SparkSession


from flask import render_template, url_for, flash, redirect, request, abort

from configuration import (
    get_args, get_db_uri #, get_templates_list,
    #BASE_DIR, MEME_DIR, FONT_PATH
    )

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'be17fdbf8e0b2b61967163422eb0c559'
app.config['SQLALCHEMY_DATABASE_URI'] = get_db_uri()
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

#modelos 

class Utilizador(db.Model, UserMixin):
    __tablename__ = 'utilizador'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20),nullable=False, default='1')
    password = db.Column(db.String(60), nullable=False)
    questions = db.relationship('Question', backref='author', lazy=True)

    def __repr__(self):
        return "" #f'User( "{self.username}", "{self.email}", "{self.image_file}")'""


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('utilizador.id'), nullable=False, default='default.jpg')
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date_closed = db.Column(db.DateTime)
    score = db.Column(db.Integer, nullable=False, default=10)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    #relacoes
    answer = db.relationship('Answer', backref='question', lazy=True)
    tags = relationship("Tag", secondary="question_tag", backref=db.backref('tags', lazy='dynamic'))

    def __repr__(self):
        #return f"Qestion('{self.title}', '{self.date_posted}')"
        return ""


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(10000), nullable =False)
    creation_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('utilizador.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    score = db.Column(db.Integer)

    def __repr__(self):
        return "" #f"Answer({self.body}','{self.creation_date}','{self.score}','{self.user_id}','{self.question_id})"

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable =False)
    #questions = relationship("Question", secondary="question_tag", backref=db.backref('questions', lazy='dynamic'))

    def __repr__(self):
        return ""#f"Tag({self.name})"


class QuestionTag(db.Model):
    __tablename__ = 'question_tag'
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'))


#routes
@app.before_first_request
def setup_db():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return Utilizador.query.get(int(user_id))

@app.route("/")
@app.route("/home")
def home():
    questions = Question.query.all()
    return render_template('home.html', questions=questions)


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = Utilizador(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = Utilizador.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        #if form.picture.data:
            #picture_file = save_picture(form.picture.data)
            #current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)


@app.route("/question/new", methods=['GET', 'POST'])
@login_required
def new_question():
    form = QuestionForm()
    if form.validate_on_submit():
        question = Question(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(question)
        question = Question.query.filter_by(title=form.title.data, content=form.content.data, author=current_user).first()
        tags = form.tag.data.split(',')
        for tag in tags:
            t = Tag.query.filter_by(name=tag).count()
            if t == 0:
                tg = Tag(name = tag)
                db.session.add(tg)
                tg_id = Tag.query.filter_by(name=tag).first()
                qt = QuestionTag(question_id = question.id,tag_id = tg_id.id)
                db.session.add(qt)
            else:
                tg = Tag.query.filter_by(name=tag).first()
                qt = QuestionTag(question_id = question.id, tag_id = tg.id)
                db.session.add(qt)
        db.session.commit()
        flash('Your question has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_question.html', title='New Question',
                           form=form, legend='New Question')


@app.route("/question/<int:question_id>")
def question(question_id):
    question = Question.query.get_or_404(question_id)
    answers = Answer.query.filter_by(question_id=question.id).all()
    lista = []
    for a in answers:
        u = Utilizador.query.get_or_404(a.user_id)
        x = Answer_owner(u , a.score, a.body, a.id)
        lista.append(x)
    return render_template('question.html', title=question.title, question=question, answers=lista)

class Answer_owner:
  def __init__(self, user, score, body, id):
    
    self.user = user
    self.score = score
    self.body = body
    self.id = id



@app.route("/question/<int:question_id>/update", methods=['GET', 'POST'])
@login_required
def update_question(question_id):
    question = Question.query.get_or_404(question_id)
    if question.author != current_user:
        abort(403)
    form = QuestionForm()
    if form.validate_on_submit():
        question.title = form.title.data
        question.content = form.content.data
        listaTag = QuestionTag.query.filter_by(question_id = question_id)
        for l in listaTag:
            db.session.delete(l)

        tags = form.tag.data.split(',')

        for tag in tags:
            t = Tag.query.filter_by(name=tag)
            if t.count() == 0:
                tg = Tag(name = tag)
                db.session.add(tg)
                tg = Tag.query.filter_by(name=tag).first()
                qt = QuestionTag(question_id = question.id,tag_id = tg.id)
                db.session.add(qt)
            else:
                tg = Tag.query.filter_by(name=tag).first()
                qt = QuestionTag(question_id = question.id,tag_id = tg.id)
                db.session.add(qt)
        
        db.session.commit()
        flash('Your question has been updated!', 'success')
        return redirect(url_for('question', question_id=question.id))
    elif request.method == 'GET':
        form.title.data = question.title
        form.content.data = question.content
        form.tag.data= tagToString(question.tags)
    return render_template('create_question.html', title='Update question',
                           form=form, legend='Update Question')

def tagToString(tags):
    str1 = ''
    for t in tags:
        str1 += t.name
    return str1


@app.route("/question/<int:question_id>/delete", methods=['POST'])
@login_required
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)
    answers = Answer.query.filter_by(question_id= question_id).all()
    if question.author != current_user:
        abort(403)
    for answer in answers:
        db.session.delete(answer)
    db.session.delete(question)
    db.session.commit()
    flash('Your question has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route("/answer/<int:question_id>/create", methods=['GET', 'POST'])
@login_required
def new_answer(question_id):
    form = AnswerForm()
    question = Question.query.filter_by(id=question_id).first()
    if form.validate_on_submit():
        answer = Answer(body = form.body.data, user_id=current_user.get_id(), question_id = question_id, score = 1)
        db.session.add(answer)
        db.session.commit()
        flash('Answer added!', 'success')
        return redirect(url_for('question', question_id=answer.question_id))
    return render_template('create_answer.html', title=question.title, form=form, legend='New Answer')

@app.route("/answer/<int:answer_id>/update", methods=['GET', 'POST'])
@login_required
def update_answer(answer_id):
    answer = Answer.query.get_or_404(answer_id)
    question = Question.query.filter_by(id=answer.question_id).first()
    if int(answer.user_id) != int(current_user.get_id()): #and question.author != current_user:
        abort(403)
    form = AnswerForm()
    if form.validate_on_submit():
        answer.body = form.body.data
        db.session.commit()
        flash('Your answer has been updated!', 'success')
        
        return redirect(url_for('question',question_id=question.id))     
    elif request.method == 'GET':
        form.body.data = answer.body
    return render_template('create_answer.html', title='Update Answer', form=form, legend='Update Answer')


@app.route("/answer/<int:answer_id>/delete", methods=['POST'])
@login_required
def delete_answer(answer_id):
    answer = Answer.query.get_or_404(answer_id)
    question = Question.query.filter_by(id=answer.question_id).first()
    if int(answer.user_id) != int(current_user.get_id()): #and question.author != current_user:
        abort(403)
    db.session.delete(answer)
    db.session.commit()
    flash('Your answer has been deleted!', 'success')
    return redirect(url_for('question', question_id=question.id))


##########################################################################

class QuestionLanguage(db.Model):
    __tablename__ = 'question_language'
    language = db.Column(db.String(50), primary_key=True)
    count = db.Column(db.Integer)


class AnswerLanguage(db.Model):
    __tablename__ = 'answer_language'
    language = db.Column(db.String(50), primary_key=True)
    count = db.Column(db.Integer)

class AllLanguage(db.Model):
    __tablename__ = 'all_language'
    language = db.Column(db.String(50), primary_key=True)
    count = db.Column(db.Integer)




@app.route("/languages")
def languages():

    languages = AllLanguage.query.order_by(AllLanguage.count.desc()).filter(AllLanguage.language != 'none').limit(10).all()
    total = len(languages)
    questions = []
    answers = []

    for lang in languages:
        question = QuestionLanguage.query.filter_by(language=lang.language).first()
        if QuestionLanguage.query.filter_by(language=lang.language).count() != 0: 
            questions.append(question.count)
        else:
            questions.append(0)

        answer = AnswerLanguage.query.filter_by(language=lang.language).first()
        if AnswerLanguage.query.filter_by(language=lang.language).count() != 0:
            answers.append(answer.count)
        else:
            answers.append(0)
    
    return render_template('languages.html', languages=languages, questions=questions, answers=answers, total=total)

#####################################################################################


class AllFrameworks(db.Model):
    __tablename__ = 'all_framework'
    framework = db.Column(db.String(50), primary_key=True)
    count = db.Column(db.Integer)

@app.route("/frameworks")
def frameworks():

    frameworks = Allframeworks.query.order_by(Allframeworks.count.desc()).filter(Allframeworks.framework != 'none').limit(10).all()
    total = len(frameworks)
   
    return render_template('frameworks.html', frameworks=frameworks, total=total)
#####################################################################################

class QuestionTag(db.Model):
    __tablename__ = 'question_Tag'
    tag = db.Column(db.String(50), primary_key=True)
    count = db.Column(db.Integer)

class MoreUsedTag(db.Model):
    __tablename__ = 'more_used_tag'
    tag = db.Column(db.Integer, primary_key=True)
    tagname = db.Column(db.String(50))
    times = db.Column(db.String(50))
 
    @app.route("/tags")
    def users():
    
        questions = QuestionTag.query.order_by(QuestionTag.count.desc()).limit(3).all()
        q = len(questions)
       
        moreUsed = MoreUsedTag.query.limit(3).all()
        s = len(moreUsed)

        return render_template('users.html', questions=questions, moreUsed = moreUsed ,q=q,s=s)
   

#####################################################################################

class QuestionsUsers(db.Model):
    __tablename__ = 'questions_users'
    user = db.Column(db.Integer, primary_key=True)
    sum = db.Column(db.Integer)
    count = db.Column(db.Integer)
    average = db.Column(db.Float)
    username = db.Column(db.String(50))

class AnswersUsers(db.Model):
    __tablename__ = 'answers_users'
    user = db.Column(db.Integer, primary_key=True)
    sum = db.Column(db.Integer)
    count = db.Column(db.Integer)
    average = db.Column(db.Float)
    username = db.Column(db.String(50))

class ExpertUsers(db.Model):
    __tablename__ = 'expert_users'
    user = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    expertise = db.Column(db.String(50))
    status = db.Column(db.String(50))
    average = db.Column(db.Float)

class SkilledUsers(db.Model):
    __tablename__ = 'skilled_users'
    user = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    expertise = db.Column(db.String(50))
    status = db.Column(db.String(50))
    average = db.Column(db.Float)


@app.route("/users")
def users():
    
    questions = QuestionsUsers.query.order_by(QuestionsUsers.count.desc()).limit(3).all()
    q = len(questions)
    answers = AnswersUsers.query.order_by(AnswersUsers.count.desc()).limit(3).all()
    a = len(answers)
    av_questions = QuestionsUsers.query.order_by(QuestionsUsers.average.desc()).limit(3).all()
    avq = len(av_questions)
    av_answers = AnswersUsers.query.order_by(AnswersUsers.average.desc()).limit(3).all()
    ava = len(av_answers)
    experts = ExpertUsers.query.limit(3).all()
    e = len(experts)
    skilled = SkilledUsers.query.limit(3).all()
    s = len(skilled)

    return render_template('users.html', questions=questions,answers=answers,experts=experts,skilled=skilled,av_questions=av_questions,av_answers=av_answers,q=q,a=a,avq=avq,ava=ava,e=e,s=s)



#forms
class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = Utilizador.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = Utilizador.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = Utilizador.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = Utilizador.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')


class QuestionForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    tag = StringField('Tag')
    submit = SubmitField('Question')


class AnswerForm(FlaskForm):
    body = TextAreaField('Body', validators=[DataRequired()])
    submit = SubmitField('Submit')


if __name__ == '__main__':
    # Run dev server (for debugging only)
    args = get_args()
    app.run(host=args.host, port=args.port, debug=True)


