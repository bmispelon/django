import unittest

try:
    import docutils
except ImportError:
    docutils = None

from django.conf import settings
from django.contrib.admindocs import utils
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.test import TestCase
from django.test.utils import override_settings

class ContribSitesTests(TestCase):
    urls = 'admin_docs.urls'

    def setUp(self):
        self.old_Site_meta_installed = Site._meta.installed
        Site._meta.installed = True
        User.objects.create_superuser('super', None, 'secret')
        self.client.login(username='super', password='secret')

    def tearDown(self):
        Site._meta.installed = self.old_Site_meta_installed

    def test_with_sites_framework(self):
        """
        Admin docs should work with contrib.sites installed.
        """
        response = self.client.get('/admindocs/views/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "<h1>View documentation</h1>")

    @override_settings(
        SITE_ID=None,
        INSTALLED_APPS=[app for app in settings.INSTALLED_APPS if app != 'django.contrib.sites']
    )
    def test_no_sites_framework(self):
        """
        Admindocs should work even if contrib.sites is not installed.
        """
        del settings.SITE_ID  # It's safe to do so because this test is wrapped in @override_settings
        Site._meta.installed = False
        response = self.client.get('/admindocs/views/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "<h1>View documentation</h1>")


@override_settings(PASSWORD_HASHERS=('django.contrib.auth.hashers.SHA1PasswordHasher',))
class XViewMiddlewareTest(TestCase):
    fixtures = ['data.xml']
    urls = 'admin_docs.urls'

    def test_xview_func(self):
        user = User.objects.get(username='super')
        response = self.client.head('/xview/func/')
        self.assertFalse('X-View' in response)
        self.client.login(username='super', password='secret')
        response = self.client.head('/xview/func/')
        self.assertTrue('X-View' in response)
        self.assertEqual(response['X-View'], 'admin_docs.views.xview')
        user.is_staff = False
        user.save()
        response = self.client.head('/xview/func/')
        self.assertFalse('X-View' in response)
        user.is_staff = True
        user.is_active = False
        user.save()
        response = self.client.head('/xview/func/')
        self.assertFalse('X-View' in response)

    def test_xview_class(self):
        user = User.objects.get(username='super')
        response = self.client.head('/xview/class/')
        self.assertFalse('X-View' in response)
        self.client.login(username='super', password='secret')
        response = self.client.head('/xview/class/')
        self.assertTrue('X-View' in response)
        self.assertEqual(response['X-View'], 'admin_docs.views.XViewClass')
        user.is_staff = False
        user.save()
        response = self.client.head('/xview/class/')
        self.assertFalse('X-View' in response)
        user.is_staff = True
        user.is_active = False
        user.save()
        response = self.client.head('/xview/class/')
        self.assertFalse('X-View' in response)


@unittest.skipUnless(docutils, "no docutils installed.")
class DefaultRoleTest(TestCase):
    urls = 'admin_docs.urls'

    def test_parse_rst(self):
        """
        Tests that ``django.contrib.admindocs.utils.parse_rst`` uses
        ``cmsreference`` as the default role.
        """
        markup = ('<p><a class="reference external" href="/admindocs/%s">'
                  'title</a></p>\n')
        self.assertEqual(utils.parse_rst('`title`', 'model'),
                         markup % 'models/title/')
        self.assertEqual(utils.parse_rst('`title`', 'view'),
                         markup % 'views/title/')
        self.assertEqual(utils.parse_rst('`title`', 'template'),
                         markup % 'templates/title/')
        self.assertEqual(utils.parse_rst('`title`', 'filter'),
                         markup % 'filters/#title')
        self.assertEqual(utils.parse_rst('`title`', 'tag'),
                         markup % 'tags/#title')

    def test_publish_parts(self):
        """
        Tests that Django hasn't broken the default role for interpreted text
        when ``publish_parts`` is used directly, by setting it to
        ``cmsreference``. See #6681.
        """
        self.assertNotEqual(docutils.parsers.rst.roles.DEFAULT_INTERPRETED_ROLE,
                            'cmsreference')
        source = 'reST, `interpreted text`, default role.'
        markup = '<p>reST, <cite>interpreted text</cite>, default role.</p>\n'
        parts = docutils.core.publish_parts(source=source, writer_name="html4css1")
        self.assertEqual(parts['fragment'], markup)
