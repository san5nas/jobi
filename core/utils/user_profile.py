def get_user_profile_info(user):
    info = {
        "id": user.id,
        "email": user.email,
        "user_type": user.user_type,
        "phone_number": user.phone_number,
        "full_name": user.full_name,  # 🆕 ყველასთვის
    }

    if user.user_type == "job_seeker" and hasattr(user, "jobseekerprofile"):
        profile = user.jobseekerprofile
        info.update({
            "profile_image": profile.profile_image.url if profile.profile_image else None,
        })

    elif user.user_type == "employer" and hasattr(user, "employerprofile"):
        profile = user.employerprofile
        info.update({
            "company_name": profile.company_name,
            "contact_person": profile.contact_person,
            "profile_image": profile.profile_image.url if profile.profile_image else None,
            "is_approved_by_admin": profile.is_approved_by_admin,
        })

    elif user.user_type == "admin" and hasattr(user, "adminprofile"):
        profile = user.adminprofile
        info.update({
            "phone": profile.phone,  # AdminProfile-ს დამატებითი ველი
            "profile_image": None,
        })

    return info
