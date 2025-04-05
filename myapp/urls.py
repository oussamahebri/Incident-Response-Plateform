from django.urls import path
from . import views


urlpatterns =[
    path("", views.index, name='index' ),
    path('wazuh/',views.alerts, name='alerts'),
    path('chatbot',views.chatbot, name='chatbot'),
    path('chat', views.chat_page, name='chat_page'),
    path('login/', views.loginPage, name='login'),
    path('register/', views.registerPage, name='register'),
    path('logout/', views.logoutUser, name='logout'),
    path('profile/', views.profile, name='profile'),

]