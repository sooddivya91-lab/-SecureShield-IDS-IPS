from scapy.all import sniff, IP, TCP
from datetime import datetime
from database import db, Alert, BlockedIP
from firewall import block_ip
import time

packet_counter = {}
port_scan_tracker = {}
last_alert_time = {}

THRESHOLD = 20
PORT_SCAN_THRESHOLD = 10
ALERT_COOLDOWN = 60  # seconds


def can_generate_alert(ip, attack_type):
    key = f"{ip}_{attack_type}"
    now = time.time()

    if key not in last_alert_time:
        last_alert_time[key] = now
        return True

    if now - last_alert_time[key] > ALERT_COOLDOWN:
        last_alert_time[key] = now
        return True

    return False


def create_alert(ip, attack_type, severity='HIGH'):

    if not can_generate_alert(ip, attack_type):
        return

    alert = Alert(
        ip=ip,
        attack_type=attack_type,
        severity=severity,
        timestamp=str(datetime.now())
    )

    db.session.add(alert)
    db.session.commit()

    existing = BlockedIP.query.filter_by(ip=ip).first()

    if not existing:
        block_ip(ip)

        blocked = BlockedIP(
            ip=ip,
            timestamp=str(datetime.now())
        )

        db.session.add(blocked)
        db.session.commit()


def process_packet(packet, socketio):

    if packet.haslayer(IP):

        ip = packet[IP].src

        packet_counter[ip] = packet_counter.get(ip, 0) + 1

        socketio.emit('packet_update', {
            'count': sum(packet_counter.values())
        })

        # DoS Detection
        if packet_counter[ip] > THRESHOLD:

            create_alert(ip, 'Possible ICMP Flood / DoS Attack')

            socketio.emit('new_alert', {
                'ip': ip,
                'attack': 'Possible ICMP Flood / DoS Attack'
            })

            packet_counter[ip] = 0

        # TCP Detection
        if packet.haslayer(TCP):

            dport = packet[TCP].dport

            # Port Scan Detection
            if ip not in port_scan_tracker:
                port_scan_tracker[ip] = set()

            port_scan_tracker[ip].add(dport)

            if len(port_scan_tracker[ip]) > PORT_SCAN_THRESHOLD:

                create_alert(ip, 'Port Scan Detected')

                socketio.emit('new_alert', {
                    'ip': ip,
                    'attack': 'Port Scan Detected'
                })

                port_scan_tracker[ip].clear()

            # Brute Force Detection
            if dport in [22, 23, 3389]:

                packet_counter[ip] += 1

                if packet_counter[ip] > 30:

                    create_alert(ip, 'Possible Brute Force Attack')

                    socketio.emit('new_alert', {
                        'ip': ip,
                        'attack': 'Possible Brute Force Attack'
                    })

                    packet_counter[ip] = 0


def start_sniffing(app, socketio):
    with app.app_context():
        sniff(prn=lambda pkt: process_packet(pkt, socketio), store=False)