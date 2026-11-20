from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from .models import UserProfile

class AccountsTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testanalyst',
            email='analyst@cyberlens.local',
            password='TestPassword123!',
            first_name='Alex',
            last_name='Vance'
        )

    def test_user_profile_signal_creation(self):
        """Test that UserProfile is automatically created when a User is created."""
        self.assertTrue(hasattr(self.user, 'profile'))
        self.assertTrue(self.user.profile.api_key.startswith('cl_'))
        self.assertEqual(self.user.profile.get_initials(), 'AV')

    def test_user_login(self):
        """Test authentication via login view."""
        response = self.client.post(reverse('accounts:login'), {
            'username': 'testanalyst',
            'password': 'TestPassword123!'
        })
        self.assertRedirects(response, reverse('dashboard:index'))

    def test_user_registration(self):
        """Test user registration form and profile population."""
        response = self.client.post(reverse('accounts:register'), {
            'username': 'newauditor',
            'email': 'auditor@cyberlens.local',
            'first_name': 'Sam',
            'last_name': 'Fisher',
            'password': 'StrongPassword456!',
            'password_confirm': 'StrongPassword456!',
            'organization': 'Cyber Security Dept',
            'job_title': 'SecOps Lead'
        })
        self.assertRedirects(response, reverse('dashboard:index'))
        new_user = User.objects.get(username='newauditor')
        self.assertEqual(new_user.profile.organization, 'Cyber Security Dept')
        self.assertEqual(new_user.profile.job_title, 'SecOps Lead')

    def test_api_key_regeneration(self):
        """Test regenerating API key."""
        self.client.login(username='testanalyst', password='TestPassword123!')
        old_key = self.user.profile.api_key
        response = self.client.post(reverse('accounts:regenerate_api_key'))
        self.assertRedirects(response, reverse('accounts:settings'))
        self.user.profile.refresh_from_db()
        self.assertNotEqual(old_key, self.user.profile.api_key)
        self.assertTrue(self.user.profile.api_key.startswith('cl_'))
