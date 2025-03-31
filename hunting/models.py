from django.db import models

# Create your models here.

class Process(models.Model):
    name = models.CharField(max_length=255)
    pid = models.IntegerField()
    path = models.CharField(max_length=500, null=True, blank=True)
    hash_value = models.CharField(max_length=64, blank=True, null=True)
    detected = models.BooleanField(default=False)

class NetworkConnection(models.Model):
    local_ip = models.GenericIPAddressField()
    local_port = models.IntegerField()
    remote_ip = models.GenericIPAddressField(null=True, blank=True)  # Allow NULL values
    remote_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10)
    detected = models.BooleanField(default=False)

class RegistryKey(models.Model):
    key = models.TextField()
    value = models.TextField()
    detected = models.BooleanField(default=False)

class AutorunEntry(models.Model):
    name = models.CharField(max_length=255)
    path = models.TextField()
    detected = models.BooleanField(default=False)

class IOC(models.Model):
    ioc_type = models.CharField(max_length=20, choices=[("process", "Process"), ("ip", "IP Address")])
    value = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return f"{self.ioc_type}: {self.value}"
