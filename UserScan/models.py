from django.db import models
from django.contrib.auth.models import User  # user tablosunu çektim

# Create your models here.


class Nmap(models.Model):
    host_ip = models.CharField(max_length=50)
    scan_type = models.CharField(max_length=50, default='SynScan')
    port = models.CharField(max_length=5000)
    state = models.CharField(max_length=5000)
    service = models.CharField(max_length=5000)
    script = models.TextField()
    scan_date = models.DateTimeField(auto_now_add=True) # tarih saat otomatik eklenir.
    user = models.ForeignKey(User, default=None, on_delete=models.CASCADE)  # foreign key

class Who_is(models.Model):
    domain_name = models.TextField(null=True)
    registrar = models.TextField(null=True)
    whois_server = models.TextField(null=True)
    referral_url = models.TextField(null=True)
    updated_date = models.TextField(null=True)
    creation_date = models.TextField(null=True)
    expiration_date = models.TextField(null=True)
    name_servers = models.TextField(null=True)
    status = models.TextField(null=True)
    emails = models.TextField(null=True)
    dnssec = models.TextField(null=True)
    name = models.TextField(null=True)
    org = models.TextField(null=True)
    address = models.TextField(null=True)
    city = models.TextField(null=True)
    state = models.TextField(null=True)
    zipcode = models.TextField(null=True)
    country = models.TextField(null=True)
    scan_date = models.DateTimeField(auto_now_add=True) # tarih saat otomatik eklenir.
    user = models.ForeignKey(User, default=None, on_delete=models.CASCADE)  # foreign key
