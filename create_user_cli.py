import os
import django

# Django სეტინგების ჩატვირთვა
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "job_platform_project.settings")
django.setup()

from core.models import User

def create_user():
    print("მომხმარებლის შექმნა")
    
    username = input("Username: ").strip()
    email = input("Email: ").strip()
    password = input("Password: ").strip()
    
    print("აირჩიე ტიპი: ")
    print("1 - Employer (დამსაქმებელი)")
    print("2 - Job Seeker (სამუშაოს მაძიებელი)")
    print("3 - Admin (ადმინსტრატორი)")
    
    type_choice = input("Type (1/2/3): ").strip()
    user_type_map = {"1": "employer", "2": "job_seeker", "3": "admin"}
    
    user_type = user_type_map.get(type_choice)
    if not user_type:
        print("არასწორი ტიპი! პროცესის შეწყვეტა.")
        return

    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        is_active=True,
     
    )
    user.user_type = user_type
    user.save()

    print(f"მომხმარებელი შექმნილია: {username}, ტიპი: {user_type}")

if __name__ == "__main__":
    create_user()
