from django.db import migrations, models

def copy_langs_forward(apps, schema_editor):
    JobSeekerLanguage = apps.get_model("core", "JobSeekerLanguage")

    # ძველი ავტომატური M2M ცხრილი
    table = "core_jobseekerprofile_languages"

    with schema_editor.connection.cursor() as cursor:
        try:
            cursor.execute(f"SELECT jobseekerprofile_id, language_id FROM {table}")
        except Exception:
            return  # არ არსებობს — არაფერს ვაკეთებთ
        rows = cursor.fetchall()
        for profile_id, language_id in rows:
            JobSeekerLanguage.objects.get_or_create(
                profile_id=profile_id,
                language_id=language_id,
                defaults={"level": "B1"},
            )

class Migration(migrations.Migration):

    dependencies = [
        ("core", "0018_skill_myjobseekerprofile_education_jobseekerlanguage_and_more"),
    ]

    operations = [
        # 1) models state: ახლა უკვე through=JobSeekerLanguage
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="jobseekerprofile",
                    name="languages",
                    field=models.ManyToManyField(
                        blank=True,
                        through="core.JobSeekerLanguage",
                        to="core.language",
                    ),
                ),
            ],
            database_operations=[],
        ),
        # 2) გადავიტანოთ ძველი კავშირები ახალ through-ში
        migrations.RunPython(copy_langs_forward, migrations.RunPython.noop),
        # 3) ძველი ავტომატური m2m ცხრილის წაშლა (თუ არსებობს)
        migrations.SeparateDatabaseAndState(
            state_operations=[],
            database_operations=[
                migrations.RunSQL(
                    "DROP TABLE IF EXISTS core_jobseekerprofile_languages",
                    reverse_sql=migrations.RunSQL.noop,
                )
            ],
        ),
    ]
