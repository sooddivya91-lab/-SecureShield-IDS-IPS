from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default='HIGH')
    timestamp = db.Column(db.String(100), nullable=False)

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.String(100), nullable=False)