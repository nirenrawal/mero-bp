from django.db import models
from django.contrib.auth.models import User

class UserInfo(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # address
    address = models.CharField(max_length=100, blank=True)
    # phone
    phone = models.CharField(max_length=15, blank=True)

    #Profile image
    profile_image = models.ImageField(upload_to='profile_image', blank=True)

    def __str__(self):
        return self.user.username


