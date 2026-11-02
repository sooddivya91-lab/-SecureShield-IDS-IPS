from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_socketio import SocketIO
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from database import db, User, Alert, BlockedIP
from detector import start_sniffing
import threading
import pandas as pd
from reportlab.pdfgen import canvas
from io import BytesIO
import requests
from sqlalchemy import func
from flask import render_template, redirect
from flask_login import login_required

app = Flask(__name__)
app.secret_key = 'supersecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///idsips.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class LoginUser(UserMixin):
    def __init__(self, user):
        self.id = user.id
        self.username = user.username

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return LoginUser(user) if user else None

with app.app_context():
    db.create_all()

    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin123')
        db.session.add(admin)
        db.session.commit()

sniffer_thread = threading.Thread(target=start_sniffing, args=(app, socketio), daemon=True)
sniffer_thread.start()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            login_user(LoginUser(user))
            return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():

    # Counts
    alert_count = Alert.query.count()
    blocked_count = BlockedIP.query.count()

    # Recent alerts
    recent_alerts = Alert.query.order_by(Alert.id.desc()).limit(5).all()

    # Attack distribution
    attack_data = db.session.query(
        Alert.attack_type,
        db.func.count(Alert.id)
    ).group_by(Alert.attack_type).all()

    attack_labels = [a[0] for a in attack_data]
    attack_values = [a[1] for a in attack_data]

    # Severity distribution
    severity_data = db.session.query(
        Alert.severity,
        db.func.count(Alert.id)
    ).group_by(Alert.severity).all()

    severity_labels = [s[0] for s in severity_data]
    severity_values = [s[1] for s in severity_data]

    return render_template(
        'index.html',
        alert_count=alert_count,
        blocked_count=blocked_count,
        recent_alerts=recent_alerts,
        attack_labels=attack_labels,
        attack_values=attack_values,
        severity_labels=severity_labels,
        severity_values=severity_values
    )
@app.route('/alerts')
@login_required
def alerts():
    return render_template(
        'alerts.html',
        alerts=Alert.query.order_by(Alert.id.desc()).all()
    )

@app.route('/blocked')
@login_required
def blocked():
    return render_template(
        'blocked.html',
        blocked=BlockedIP.query.order_by(BlockedIP.id.desc()).all()
    )

@app.route('/export/csv')
@login_required
def export_csv():
    alerts = Alert.query.all()

    df = pd.DataFrame([{
        'IP': a.ip,
        'Attack Type': a.attack_type,
        'Severity': a.severity,
        'Timestamp': a.timestamp
    } for a in alerts])

    path = 'alerts.csv'
    df.to_csv(path, index=False)

    return send_file(path, as_attachment=True)

@app.route('/export/pdf')
@login_required
def export_pdf():
    buffer = BytesIO()
    p = canvas.Canvas(buffer)

    y = 800
    p.drawString(50, y, 'SecureShield IDS/IPS Alert Report')
    y -= 30

    for a in Alert.query.all():
        p.drawString(50, y, f'{a.ip} | {a.attack_type} | {a.timestamp}')
        y -= 20

        if y < 50:
            p.showPage()
            y = 800

    p.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name='alerts.pdf',
        mimetype='application/pdf'
    )
@app.route('/geoip/<ip>')
@login_required
def geoip(ip):
    try:
        response = requests.get(f'https://ipapi.co/{ip}/json/').json()

        data = {
            'ip': ip,
            'city': response.get('city'),
            'region': response.get('region'),
            'country': response.get('country_name'),
            'latitude': response.get('latitude'),
            'longitude': response.get('longitude')
        }

        return render_template('geoip.html', data=data)

    except Exception as e:
        return str(e)
@app.route('/traffic')
@login_required
def traffic():
    return render_template('traffic.html')

@app.route('/portscan')
@login_required
def portscan():
    data = Alert.query.filter(Alert.attack_type.contains('Port Scan')).all()
    return render_template('portscan.html', alerts=data)

@app.route('/bruteforce')
@login_required
def bruteforce():
    data = Alert.query.filter(Alert.attack_type.contains('Brute Force')).all()
    return render_template('bruteforce.html', alerts=data)

@app.route('/reports')
@login_required
def reports():
    total_alerts = Alert.query.count()
    total_blocked = BlockedIP.query.count()
    return render_template(
        'reports.html',
        total_alerts=total_alerts,
        total_blocked=total_blocked
    )

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')
@app.route('/simulate/<attack>')
@login_required
def simulate_attack(attack):

    from datetime import datetime

    fake_ip = '192.168.1.100'

    if attack == 'portscan':
        attack_type = 'Port Scan Detected'

    elif attack == 'bruteforce':
        attack_type = 'Possible Brute Force Attack'

    elif attack == 'dos':
        attack_type = 'Possible ICMP Flood / DoS Attack'

    else:
        attack_type = 'Unknown Attack'

    alert = Alert(
        ip=fake_ip,
        attack_type=attack_type,
        severity='HIGH',
        timestamp=str(datetime.now())
    )

    db.session.add(alert)
    db.session.commit()

    return redirect(url_for('alerts'))


@app.route('/lab')
@login_required
def lab():
    return render_template('simulation.html')
@app.route('/reset_alerts')
def reset_alerts():
    Alert.query.delete()
    BlockedIP.query.delete()
    db.session.commit()
    return redirect('/')
if __name__ == '__main__':
    socketio.run(app, debug=True)