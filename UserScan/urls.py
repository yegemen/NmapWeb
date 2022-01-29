from django.urls import path
from . import views

urlpatterns = [
    path('', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('scan/', views.scan, name='scan'),
    path('select/', views.select, name='select'),
    path('who_is/', views.who_is, name='who_is'),
    path('past_scanning/', views.past_scanning, name='past_scanning'),
    path('past_scanning_whois/', views.past_scanning_whois, name='past_scanning_whois'),
    path('logout/', views.logout, name= 'logout'),
]