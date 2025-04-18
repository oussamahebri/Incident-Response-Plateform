# Generated by Django 5.1.6 on 2025-03-08 11:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='alert',
            fields=[
                ('alert_id', models.AutoField(primary_key=True, serialize=False)),
                ('id', models.IntegerField()),
                ('timestamp', models.DateTimeField()),
                ('criticity', models.CharField(choices=[('low', 'low'), ('medium', 'medium'), ('critical', 'critical')], max_length=8)),
                ('computer', models.CharField(max_length=255)),
                ('account_name', models.CharField(blank=True, max_length=255, null=True)),
                ('source', models.CharField(max_length=50)),
                ('destination', models.CharField(blank=True, max_length=50, null=True)),
                ('description', models.TextField()),
            ],
            options={
                'db_table': 'alert',
            },
        ),
    ]
