from django.db import models

# Create your models here.

class Alert(models.Model):
    alert_id = models.AutoField(primary_key=True)
    rule_id = models.IntegerField()
    timestamp = models.DateTimeField()
    criticity = models.CharField(max_length=8, choices=[('low', 'low'), ('medium', 'medium'), ('critical', 'critical')])
    target_name = models.CharField(max_length=255)
    target_ip = models.CharField(max_length=50)
    attacker = models.CharField(max_length=50, null=True, blank=True)
    alert_desc = models.TextField()
    status = models.CharField(max_length=8, choices=[('pending', 'pending'), ('resolved', 'resolved'), ('error', 'error')])
    incident_response_desc = models.TextField(db_column='Incident_Response_Desc')


    class Meta:
        db_table = 'alert'

    def __str__(self):
        return f"{self.timestamp}"
    
    