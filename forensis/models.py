from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='analyst') # 'admin', 'analyst'
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)

    group = db.relationship('Group', backref='users')

    def __repr__(self):
        return f'<User {self.username}>'

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f'<Group {self.name}>'

class AnalysisHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False) # 'logs', 'network', 'memory'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    results_json = db.Column(db.Text, nullable=True) # Storing JSON as text
    filename = db.Column(db.String(255), nullable=True)

    user = db.relationship('User', backref='analyses')

    def get_results(self):
        if self.results_json:
            return json.loads(self.results_json)
        return None
