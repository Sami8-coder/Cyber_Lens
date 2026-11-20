import secrets
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserProfile(models.Model):
    SCAN_DEPTH_CHOICES = [
        ('quick', 'Quick Scan (Fast Header & SSL Check)'),
        ('standard', 'Standard Scan (Headers, SSL, Cookies, DNS)'),
        ('deep', 'Deep Assessment (Full DNS, TLS, SPF/DMARC, CSP Analysis)'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    organization = models.CharField(max_length=150, blank=True, help_text="Company or School / Organization")
    job_title = models.CharField(max_length=100, blank=True, help_text="e.g. Security Engineer, CSE Student, Web Dev")
    api_key = models.CharField(max_length=64, unique=True, blank=True, help_text="API token for automation")
    default_scan_depth = models.CharField(max_length=20, choices=SCAN_DEPTH_CHOICES, default='standard')
    notification_email = models.BooleanField(default=True, help_text="Receive alerts and scan summaries")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} Profile"

    def get_initials(self):
        first = self.user.first_name[:1] if self.user.first_name else ''
        last = self.user.last_name[:1] if self.user.last_name else ''
        initials = (first + last).upper()
        if not initials:
            return self.user.username[:2].upper()
        return initials

    def generate_api_key(self):
        new_key = f"cl_{secrets.token_hex(24)}"
        self.api_key = new_key
        self.save(update_fields=['api_key'])
        return new_key

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = f"cl_{secrets.token_hex(24)}"
        super().save(*args, **kwargs)

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
    else:
        if hasattr(instance, 'profile'):
            instance.profile.save()
