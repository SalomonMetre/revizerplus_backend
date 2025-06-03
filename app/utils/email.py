# app/utils/email.py

from fastapi import HTTPException
from sib_api_v3_sdk import ApiClient, Configuration
from sib_api_v3_sdk.api.transactional_emails_api import TransactionalEmailsApi
from sib_api_v3_sdk.models import SendSmtpEmail
from core.config import settings
from sib_api_v3_sdk.rest import ApiException

async def send_email_via_api(recipient: str, subject: str, content: str):
    configuration = Configuration()
    configuration.api_key['api-key'] = settings.BREVO_SMTP_KEY

    api_instance = TransactionalEmailsApi(ApiClient(configuration))
    sender = {"name": "Revizer Plus", "email": settings.BREVO_EMAIL}
    to = [{"email": recipient}]

    try:
        email = SendSmtpEmail(
            sender=sender,
            to=to,
            subject=subject,
            html_content=content
        )
        return api_instance.send_transac_email(email)
    except ApiException as e:
        raise HTTPException(status_code=500, detail=f"Brevo API error: {e}")
