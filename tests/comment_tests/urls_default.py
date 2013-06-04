from django.conf.urls import patterns, include

urlpatterns = patterns('',
    (r'^', include('django.contrib.comments.urls')),

    # Provide the auth system login and logout views
    (r'^accounts/', include('django.contrib.auth.urls')),
)
