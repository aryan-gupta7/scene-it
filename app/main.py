from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, ValidationError, EqualTo, NumberRange
from wtforms import StringField, PasswordField, SubmitField, DateField, TimeField, IntegerField, TextAreaField
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta, time, date
from flask_migrate import Migrate
import re
import os
from sqlalchemy.sql import func
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['POSTGRES_URL'].replace("postgres://", "postgresql://")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
csrf = CSRFProtect(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)



# Tables
user_event_interest = db.Table('user_event_interest',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'), primary_key=True)
)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(100), nullable=False, default="Location to be decided")
    timing = db.Column(db.Time, nullable=False, default=time(18, 0))  # Default to 6:00 PM
    duration = db.Column(db.Integer, nullable=False, default=60)  # Default duration: 1 hour (60 minutes)
    type_ = db.Column(db.String(100), nullable=False, default="Not specified")
    tag = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=False, default="No description available")
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), onupdate=func.now())
    interested_users = db.relationship('User', secondary=user_event_interest, back_populates='interested_events')

    def __repr__(self):
        return f'<Event {self.name}>'
    
    @property
    def interest_count(self):
        return len(self.interested_users)

    def to_dict(self):
        today = date.today()
        return {
            'id': self.id,
            'name': self.name,
            'date': self.date.isoformat() if self.date else None,
            'location': self.location,
            'timing': self.timing.isoformat() if self.timing else None,
            'duration': self.duration,
            'type_': self.type_,
            'description': self.description,
            'interest_count': self.interest_count,
            'tag': self.tag,
            'is_past_event': (self.date < today if self.date else False) or 
                             (datetime.combine(self.date, self.timing) + timedelta(minutes=self.duration) < datetime.now() 
                              if self.date and self.timing and self.duration else False)
        }
    
    @property
    def interest_count(self):
        return len(self.interested_users)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(8), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    interested_events = db.relationship('Event', secondary=user_event_interest, back_populates='interested_users')

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    



# Forms
class LoginForm(FlaskForm):
    roll_no = StringField('Roll Number', validators=[DataRequired(), Length(min=8, max=8)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    roll_no = StringField('Username', validators=[DataRequired(), Length(min=8, max=8, message="Username must be exactly 8 digits")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_roll_no(self, roll_no):
        if not re.match(r'^\d{8}$', roll_no.data):
            raise ValidationError('Username must be exactly 8 digits.')
        user = User.query.filter_by(username=roll_no.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_password(self, password):
        if not re.search("[a-z]", password.data):
            raise ValidationError("Password must contain at least one lowercase letter.")
        if not re.search("[A-Z]", password.data):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not re.search("[0-9]", password.data):
            raise ValidationError("Password must contain at least one number.")

class EventForm(FlaskForm):
    name = StringField('Event Name', validators=[DataRequired()])
    date = DateField('Event Date', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    timing = TimeField('Timing', validators=[DataRequired()])
    duration = IntegerField('Duration (minutes)', validators=[DataRequired(), NumberRange(min=1)])
    type_ = StringField('Event Type', validators=[DataRequired()])
    tag = StringField('Tag')
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Add Event')


@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.roll_no.data).first()
        if user:
            if user.check_password(form.password.data):
                session['user_id'] = user.id
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Incorrect password. Please try again.', 'danger')
        else:
            flash('User does not exist. Please check your roll number or Register.', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(fullname=form.full_name.data, username=form.roll_no.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    now = datetime.now()
    today = now.date()
    current_time = now.time()

    # Upcoming events: today's future events and all future dates
    upcoming_events = Event.query.filter(
        ((Event.date == today) & (Event.timing > current_time)) |
        (Event.date > today)
    ).order_by(Event.date, Event.timing).all()

    # Ongoing events: today's events that have started but not ended
    ongoing_events = Event.query.filter(
        (Event.date == today) & 
        (Event.timing <= current_time) &
        (func.addtime(func.time(Event.timing), func.sec_to_time(Event.duration * 60)) > func.time(current_time))
    ).order_by(Event.timing).all()

    # Past events: previous dates and today's ended events
    past_events = Event.query.filter(
        (Event.date < today) |
        ((Event.date == today) & 
         (func.addtime(func.time(Event.timing), func.sec_to_time(Event.duration * 60)) <= func.time(current_time)))
    ).order_by(Event.date.desc(), Event.timing.desc()).limit(7).all()

    def serialize_event(event):
        event_dict = event.to_dict()
        event_dict['is_interested'] = event in user.interested_events
        
        # Check if the event has ended
        event_end_time = datetime.combine(event.date, event.timing) + timedelta(minutes=event.duration)
        if now > event_end_time:
            event_dict['is_past_event'] = True
        
        return event_dict

    upcoming_events_serialized = [serialize_event(event) for event in upcoming_events]
    ongoing_events_serialized = [serialize_event(event) for event in ongoing_events]
    past_events_serialized = [serialize_event(event) for event in past_events]

    # Filter out any events that have ended from ongoing_events
    ongoing_events_serialized = [event for event in ongoing_events_serialized if not event.get('is_past_event', False)]

    return render_template('index.html', 
                           user=user, 
                           upcoming_events=upcoming_events_serialized, 
                           ongoing_events=ongoing_events_serialized, 
                           feedback_items=past_events_serialized)


@app.route('/logout')
def logout():
    # Clear the user's session
    session.clear()
    
    # Clear any existing flash messages
    _ = get_flashed_messages()
    
    # Set the logout flash message
    flash('You have been logged out successfully.', 'info')
    
    return redirect(url_for('login'))


@app.route('/mark_interest/<int:event_id>', methods=['POST'])
def mark_interest(event_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in to mark interest.'}), 401

    user = User.query.get(session['user_id'])
    event = Event.query.get(event_id)
    if not event:
        return jsonify({'success': False, 'message': 'Event not found.'}), 404
    if event in user.interested_events:
        user.interested_events.remove(event)
        interested = False
        message = "You are no longer interested in this event."
    else:
        user.interested_events.append(event)
        interested = True
        message = "You are now interested in this event."

    try:
        db.session.commit()
        return jsonify({
            'success': True,
            'interested': interested,
            'interest_count': event.interest_count,
            'message': message
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred. Please try again.'}), 500


@app.route('/check_username')
def check_username():
    username = request.args.get('username', '')
    if not username.isdigit():
        return jsonify({'available': False, 'message': 'Username must contain only numbers'})
    user = User.query.filter_by(username=username).first()
    return jsonify({'available': user is None})


@app.route('/add_event', methods=['GET', 'POST'])
def add_event():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.username != "98210005":
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    
    form = EventForm()
    if form.validate_on_submit():
        new_event = Event(
            name=form.name.data,
            date=form.date.data,
            location=form.location.data,
            timing=form.timing.data,
            duration=form.duration.data,
            type_=form.type_.data,
            tag=form.tag.data,
            description=form.description.data
        )
        db.session.add(new_event)
        try:
            db.session.commit()
            flash('Event added successfully!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    
    return render_template('add_event.html', form=form)


if not app.debug:
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    app.logger.addHandler(stream_handler)

app.logger.setLevel(logging.INFO)
app.logger.info('Flask App Startup')


