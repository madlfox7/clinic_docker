"""Shared registration helper: every POST /register carries a name and a phone."""

PATIENT_NAME = "Test Patient"
PATIENT_PHONE = "+374 10 000111"
PATIENT_FIELDS = {"full_name": PATIENT_NAME, "phone": PATIENT_PHONE}


def registration_form(email: str, password: str, confirm_password: str | None = None, **fields) -> dict:
    data = dict(PATIENT_FIELDS)
    data.update(fields)
    data.update(
        {
            "email": email,
            "password": password,
            "confirm_password": password if confirm_password is None else confirm_password,
        }
    )
    return data
