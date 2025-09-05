from django.test import TestCase

# Create your tests here.
from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from core.models import User

class AuthTests(APITestCase):
    def test_register_and_login(self):
        # რეგისტრაცია
        response = self.client.post('/api/register/', {
            'email': 'test111@example.com',
            'password': 'sandro123',
            'user_type': 'job_seeker',
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # ვცადოთ ლოგინი
        response = self.client.post('/api/login/', {
            'email': 'test111@example.com',
            'password': 'sandro123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
