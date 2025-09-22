from django.core.management.base import BaseCommand
from core.models import Application
from utils.google import get_event_attendance_status

class Command(BaseCommand):
    help = "სინქრონიზაცია: Google Calendar ინტერვიუს პასუხები (accepted/declined/tentative)"

    def handle(self, *args, **kwargs):
        applications = Application.objects.exclude(interview_event_id__isnull=True).exclude(interview_event_id="")

        updated_count = 0
        for app in applications:
            user = app.vacancy.employer.user  # დამსაქმებლის user
            statuses, updated = get_event_attendance_status(user, app.interview_event_id)

            if not statuses:
                continue

            candidate_email = getattr(app.job_seeker, "email", None)
            candidate_status = statuses.get(candidate_email)

            if candidate_status == "declined":
                app.status = "rejected"
                app.save(update_fields=["status"])
                updated_count += 1
                self.stdout.write(self.style.WARNING(f"Application {app.id} → DECLINED ({candidate_email})"))
            elif candidate_status == "accepted":
                app.status = "interview"
                app.save(update_fields=["status"])
                updated_count += 1
                self.stdout.write(self.style.SUCCESS(f"Application {app.id} → ACCEPTED ({candidate_email})"))
            elif candidate_status == "tentative":
                self.stdout.write(f"Application {app.id} → TENTATIVE ({candidate_email})")
            elif candidate_status == "needsAction":
                self.stdout.write(f"Application {app.id} → NO RESPONSE YET ({candidate_email})")

        self.stdout.write(self.style.SUCCESS(f"სინქრონიზაცია დასრულდა. განახლდა {updated_count} განაცხადი."))
