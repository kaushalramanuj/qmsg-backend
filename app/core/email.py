from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from typing import List
import os
from dotenv import load_dotenv

load_dotenv()

conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", "587")),
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

async def send_otp_email(email: str, otp: str):
    message = MessageSchema(
        subject="Password Reset OTP",
        recipients=[email],
        body=f"""
        <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>You have requested to reset your password. Use the following OTP to proceed:</p>
                <h1 style="color: #4F46E5; font-size: 32px; letter-spacing: 5px;">{otp}</h1>
                <p>This OTP will expire in 10 minutes.</p>
                <p>If you didn't request this, please ignore this email.</p>
                <p>Best regards,<br>Q-Msg Team</p>
            </body>
        </html>
        """,
        subtype="html"
    )
    
    fm = FastMail(conf)
    await fm.send_message(message) 