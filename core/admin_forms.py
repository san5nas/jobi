from django import forms
from .models import Vacancy


class VacancyAdminForm(forms.ModelForm):
    reject = forms.BooleanField(
        required=False,
        label="❌ Reject this vacancy",
        help_text="მონიშნე თუ გსურს განცხადების უარყოფა (მიზეზი საჭიროა)"
    )

    class Meta:
        model = Vacancy
        fields = [
            "title",
            "description",
            "requirements",
            "min_salary",
            "location",
            "vacancy_type",
            "is_premium",
            "is_published",
            "is_approved",
            "reject",             # ⬅ ზემოთ!
            "rejection_reason",  # ⬅ ქვემოთ!
            "expiry_date",
            "category",
            "latitude",
            "longitude",
            "location_name",
        ]

    def clean(self):
        cleaned_data = super().clean()
        reject = cleaned_data.get("reject")
        reason = cleaned_data.get("rejection_reason")

        if reject and not reason:
            raise forms.ValidationError("გთხოვთ მიუთითეთ უარყოფის მიზეზი.")
        return cleaned_data
