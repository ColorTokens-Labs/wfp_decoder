#
# Copyright (C) 2023 ColorTokens Inc.
# By Venky Raju <venky.raju@colortokens.com>
#

from django.urls import path
from . import views

urlpatterns = [
    path('', views.main, name='main'),
    path('demo', views.demo, name='demo'),
    path('upload', views.upload, name='upload'),
    path('provider/<str:key>', views.show_provider, name='provider'),
    path('layer/<str:key>', views.show_layer, name='layer'),
    path('sublayer/<str:key>', views.show_sublayer, name='sublayer'),
]