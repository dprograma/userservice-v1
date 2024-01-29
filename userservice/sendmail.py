import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from django.conf import settings


class SendMail:
    # mail_subject, message, to=[to_email]
    def __init__(self, subject, message, to):
        self.to = to
        self.subject = subject
        self.message = message
        self.send()

    def send(self):
        port = settings.MAIL_PORT  # For starttls
        smtp_server = settings.MAIL_SERVER
        sender_email = settings.MAIL_USER
        password = settings.MAIL_PASS
        receiver_email = self.to

        message = MIMEMultipart("alternative")
        message["Subject"] = self.subject
        message["From"] = sender_email
        message["To"] = receiver_email

        # Create the plain-text and HTML version of your message
        # text = self.altmsg
        html = self.message

        # Turn these into plain/html MIMEText objects
        # part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")

        # Add HTML/plain-text parts to MIMEMultipart message
        # The email client will try to render the last part first
        # message.attach(part1)
        message.attach(part2)

        # Create secure connection with server and send email
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls(context=context)
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
