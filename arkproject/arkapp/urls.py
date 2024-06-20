from django.contrib import admin
from django.urls import path,include
from arkapp import views

urlpatterns = [
  path('',views.index,name='index')
]
