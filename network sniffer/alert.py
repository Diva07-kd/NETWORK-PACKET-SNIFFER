# alert.py
import smtplib
from email.mime.text import MIMEText
def send_alert(msg):
    print(f"ALERT: {msg}")
    # Optional: send email
    '''
    sender = "sender@example.com"
    receiver = "admin@example.com"
    body = f"Alert: {msg}"
    msg = MIMEText(body)
    msg["Subject"] = "Network Anomaly Alert"
    msg["From"] = sender
    msg["To"] = receiver
    with smtplib.SMTP('localhost') as s:
        s.sendmail(sender, [receiver], msg.as_string())
    '''