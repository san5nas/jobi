import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class PasswordComplexityValidator:
    def validate(self, password, user=None):
        # მინიმუმ ერთი ასო
        if not re.search(r'[A-Za-z]', password):
            raise ValidationError(
                _("პაროლი უნდა შეიცავდეს მინიმუმ ერთ ლათინურ ასოს."),
                code='password_no_letter',
            )

        # მინიმუმ ერთი ციფრი
        if not re.search(r'[0-9]', password):
            raise ValidationError(
                _("პაროლი უნდა შეიცავდეს მინიმუმ ერთ ციფრს."),
                code='password_no_digit',
            )

        # მხოლოდ ლათინური ასოები + ციფრები + სიმბოლოები
        if not re.fullmatch(r'[A-Za-z0-9!@#$%^&*(),.?":{}|<>]+', password):
            raise ValidationError(
                _("პაროლი უნდა შეიცავდეს მხოლოდ ლათინურ ასოებს, ციფრებს და სპეციალურ სიმბოლოებს."),
                code='password_not_latin',
            )

    def get_help_text(self):
        return _(
            "პაროლი უნდა შეიცავდეს მინიმუმ 8 სიმბოლოს, "
            "მინიმუმ ერთ ლათინურ ასოს და ერთ ციფრს. "
            "ქართული ასოები დაუშვებელია."
        )
