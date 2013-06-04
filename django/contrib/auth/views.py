try:
    from urllib.parse import urlparse, urlunparse
except ImportError:     # Python 2
    from urlparse import urlparse, urlunparse
import warnings

from django.conf import settings
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import HttpResponseRedirect, QueryDict
from django.shortcuts import resolve_url
from django.template.response import TemplateResponse
from django.utils.decorators import method_decorator
from django.utils.http import base36_to_int, is_safe_url
from django.utils.translation import ugettext as _
from django.views import generic
from django.views.generic.base import ContextMixin, TemplateResponseMixin
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

# Avoid shadowing the login() and logout() views below.
from django.contrib.auth import (REDIRECT_FIELD_NAME, login as auth_login,
                                 logout as auth_logout, get_user_model)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (AuthenticationForm, PasswordResetForm,
                                      SetPasswordForm, PasswordChangeForm)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import get_current_site


class CurrentAppMixin(object):
    """Add a current_app attribute on the view and pass it to the response class."""
    current_app = None

    def render_to_response(self, context, **response_kwargs):
        return self.response_class(
            request=self.request,
            template=self.get_template_names(),
            context=context,
            current_app=self.current_app,
            **response_kwargs
        )


class CurrentSiteMixin(object):
    """Add the current site to the context."""
    def get_context_data(self, **kwargs):
        context = super(CurrentSiteMixin, self).get_context_data(**kwargs)

        current_site = get_current_site(self.request)
        context.update({
            "site": current_site,
            "site_name": current_site.name,
        })
        return context


class LoginView(CurrentAppMixin, CurrentSiteMixin, generic.FormView):
    """Display the login form and handle the login action."""
    form_class = AuthenticationForm
    template_name = 'registration/login.html'

    redirect_field_name = REDIRECT_FIELD_NAME

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super(LoginView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(LoginView, self).get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def get_context_data(self, **kwargs):
        context = super(LoginView, self).get_context_data(**kwargs)
        context[self.redirect_field_name] = self.get_success_url()
        return context

    def form_valid(self, form):
        """Log the user in and redirect."""
        auth_login(self.request, form.get_user())
        # Redirect
        return super(LoginView, self).form_valid(form)
    
    def get_success_url(self):
        """
        Look for a redirect URL in the request parameters.
        If none is found, or if it's not valid, use settings.LOGIN_REDIRECT_URL.

        """
        redir = self.request.REQUEST.get(self.redirect_field_name)
        if not is_safe_url(url=redir, host=self.request.get_host()):
            redir = resolve_url(settings.LOGIN_REDIRECT_URL)
        return redir


class LogoutView(CurrentAppMixin, CurrentSiteMixin, ContextMixin, TemplateResponseMixin, generic.View):
    """Log out the user and display 'You are logged out' message."""
    template_name = 'registration/logged_out.html'
    redirect_field_name = REDIRECT_FIELD_NAME
    success_url = None

    def post(self, request, *args, **kwargs):
        auth_logout(request)
        redir = self.get_success_url()

        if redir is not None:
            return HttpResponseRedirect(redir)
        else:
            # Render the template
            context = self.get_context_data()
            return self.render_to_response(context)

    def get(self, request, *args, **kwargs):
        # This could be removed when #15619 is decided
        return self.post(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(LogoutView, self).get_context_data(**kwargs)
        context['title'] = _('Logged out')
        return context

    def get_success_url(self):
        """
        Look for a url to redirect to in the request parameters.
        If none is found, or if it's not valid, fall back on the
        view instance's success_url attribute.
        If that attribute has not been set (None), then return None.
        If it has but it's empty, return the current request's path.

        """
        redir = self.request.REQUEST.get(self.redirect_field_name)
        if redir is not None:
            safe = is_safe_url(redir, host=self.request.get_host())
            return redir if safe else self.request.path

        if self.success_url is not None:
            return self.success_url

        return None # Don't redirect, display a "logout successful" page


class LogoutThenLoginView(LogoutView):
    """Log out the user if he is logged in. Then redirects to the log-in page."""
    @property # Because resolve_url can't be called at compile-time.
    def success_url(self):
        return resolve_url(settings.LOGIN_URL)


class PasswordResetView(CurrentAppMixin, generic.FormView):
    """
    Ask for the user's email address and send a message containing a token
    allowing to reset the user's password.

    """
    template_name = "registration/password_reset_form.html"
    form_class = PasswordResetForm
    success_url = reverse_lazy('password_reset_done')

    is_admin_site = False
    email_template_name = "registration/password_reset_email.html"
    subject_template_name = "registration/password_reset_subject.txt"
    token_generator = default_token_generator
    from_email = None

    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordResetView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        opts = {
            'use_https': self.request.is_secure(),
            'token_generator': self.token_generator,
            'from_email': self.from_email,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
        }
        if self.is_admin_site:
            opts['domain_override'] = self.request.get_host()
        form.save(**opts)
        return super(PasswordResetView, self).form_valid(form)


class PasswordResetDoneView(CurrentAppMixin, generic.TemplateView):
    """Show a confirmation message that a password reset email has been sent."""
    template_name = "registration/password_reset_done.html"


class PasswordResetConfirmView(CurrentAppMixin, generic.FormView):
    # XXX: This one might have some backwards-compatibility issues in some corner cases.
    # In this CBV, form.user is a User instance if the token matches the uidb36,
    # even in the GET request, as opposed to the old view where form.user was
    # only set in POST).
    """
    Check that the given token is valid and prompt the user for a new pasword.
    Then update the user's password with this new one.

    """
    template_name = "registration/password_reset_confirm.html"
    form_class = SetPasswordForm
    success_url = reverse_lazy('password_reset_complete')

    token_generator = default_token_generator

    # Doesn't need csrf_protect since no-one can guess the URL
    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        self.user = self.get_user(**kwargs)
        return super(PasswordResetConfirmView, self).dispatch(request, *args, **kwargs)

    def get_user(self, **kwargs):
        """Try to retrieve the user corresponding to the uid captured in the URL.
        If no user is found, or if the user found does not match the token in
        the URL, return None.
        
        """
        UserModel = get_user_model()
        try:
            pk = base36_to_int(kwargs['uidb36'])
            user = UserModel._default_manager.get(pk=pk)
        except (ValueError, OverflowError, UserModel.DoesNotExist):
            return None

        if not self.token_generator.check_token(user, kwargs['token']):
            return None
        return user

    def get_form_kwargs(self):
        kwargs = super(PasswordResetConfirmView, self).get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def get_context_data(self, **kwargs):
        context = super(PasswordResetConfirmView, self).get_context_data(**kwargs)
        context['validlink'] = self.user is not None
        return context

    def form_valid(self, form):
        form.save()
        return super(PasswordResetConfirmView, self).form_valid(form)


class PasswordResetCompleteView(CurrentAppMixin, generic.TemplateView):
    """Show a confirmation message that the user's password has been reset."""
    template_name = "registration/password_reset_complete.html"

    def get_context_data(self, **kwargs):
        context = super(PasswordResetCompleteView, self).get_context_data(**kwargs)
        context['login_url'] = resolve_url(settings.LOGIN_URL)
        return context


class PasswordChangeView(CurrentAppMixin, generic.FormView):
    """
    Prompt the logged-in user for their current password as well as a new one.
    If the current password is valid, change it to the new one.

    """
    template_name = "registration/password_change_form.html"
    success_url = reverse_lazy('password_change_done')
    form_class = PasswordChangeForm

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordChangeView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(PasswordChangeView, self).get_form_kwargs()
        kwargs['user'] = self.request.user

        return kwargs

    def form_valid(self, form):
        form.save()
        return super(PasswordChangeView, self).form_valid(form)


class PasswordChangeDoneView(CurrentAppMixin, generic.TemplateView):
    """Show a confirmation message that the user's password has been changed."""
    template_name = "registration/password_change_done.html"

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordChangeDoneView, self).dispatch(request, *args, **kwargs)


def redirect_to_login(next, login_url=None,
                      redirect_field_name=REDIRECT_FIELD_NAME):
    """
    Redirects the user to the login page, passing the given 'next' page
    """
    resolved_url = resolve_url(login_url or settings.LOGIN_URL)

    login_url_parts = list(urlparse(resolved_url))
    if redirect_field_name:
        querystring = QueryDict(login_url_parts[4], mutable=True)
        querystring[redirect_field_name] = next
        login_url_parts[4] = querystring.urlencode(safe='/')

    return HttpResponseRedirect(urlunparse(login_url_parts))


# Legacy function-based implementation
@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request, template_name='registration/login.html',
          redirect_field_name=REDIRECT_FIELD_NAME,
          authentication_form=AuthenticationForm,
          current_app=None, extra_context=None):
    """
    Displays the login form and handles the login action.
    """
    warnings.warn("The function-based views in django.contrib.auth are deprecated. "
        "Use the class-based ones instead.", stacklevel=2)
    redirect_to = request.REQUEST.get(redirect_field_name, '')

    if request.method == "POST":
        form = authentication_form(request, data=request.POST)
        if form.is_valid():

            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to, host=request.get_host()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

            # Okay, security check complete. Log the user in.
            auth_login(request, form.get_user())

            return HttpResponseRedirect(redirect_to)
    else:
        form = authentication_form(request)

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

def logout(request, next_page=None,
           template_name='registration/logged_out.html',
           redirect_field_name=REDIRECT_FIELD_NAME,
           current_app=None, extra_context=None):
    """
    Logs out the user and displays 'You are logged out' message.
    """
    warnings.warn("The function-based views in django.contrib.auth are deprecated. "
        "Use the class-based ones instead.", stacklevel=2)
    auth_logout(request)

    if next_page is not None:
        next_page = resolve_url(next_page)

    if redirect_field_name in request.REQUEST:
        next_page = request.REQUEST[redirect_field_name]
        # Security check -- don't allow redirection to a different host.
        if not is_safe_url(url=next_page, host=request.get_host()):
            next_page = request.path

    if next_page:
        # Redirect to this page until the session has been cleared.
        return HttpResponseRedirect(next_page)

    current_site = get_current_site(request)
    context = {
        'site': current_site,
        'site_name': current_site.name,
        'title': _('Logged out')
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
        current_app=current_app)

def logout_then_login(request, login_url=None, current_app=None, extra_context=None):
    """
    Logs out the user if he is logged in. Then redirects to the log-in page.
    """
    warnings.warn("The function-based views in django.contrib.auth are deprecated. "
        "Use the class-based ones instead.", stacklevel=2)
    if not login_url:
        login_url = settings.LOGIN_URL
    login_url = resolve_url(login_url)
    return logout(request, login_url, current_app=current_app, extra_context=extra_context)

@csrf_protect
def password_reset(request, is_admin_site=False,
                   template_name='registration/password_reset_form.html',
                   email_template_name='registration/password_reset_email.html',
                   subject_template_name='registration/password_reset_subject.txt',
                   password_reset_form=PasswordResetForm,
                   token_generator=default_token_generator,
                   post_reset_redirect=None,
                   from_email=None,
                   current_app=None,
                   extra_context=None):
    warnings.warn("The function-based views in django.contrib.auth are deprecated. "
        "Use the class-based ones instead.", stacklevel=2)
    if post_reset_redirect is None:
        post_reset_redirect = reverse('password_reset_done')
    else:
        post_reset_redirect = resolve_url(post_reset_redirect)
    if request.method == "POST":
        form = password_reset_form(request.POST)
        if form.is_valid():
            opts = {
                'use_https': request.is_secure(),
                'token_generator': token_generator,
                'from_email': from_email,
                'email_template_name': email_template_name,
                'subject_template_name': subject_template_name,
                'request': request,
            }
            if is_admin_site:
                opts = dict(opts, domain_override=request.get_host())
            form.save(**opts)
            return HttpResponseRedirect(post_reset_redirect)
    else:
        form = password_reset_form()
    context = {
        'form': form,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

def password_reset_done(request,
                        template_name='registration/password_reset_done.html',
                        current_app=None, extra_context=None):
    warnings.warn("The function-based views in django.contrib.auth are deprecated. "
        "Use the class-based ones instead.", stacklevel=2)
    context = {}
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

# Doesn't need csrf_protect since no-one can guess the URL
@sensitive_post_parameters()
@never_cache
def password_reset_confirm(request, uidb36=None, token=None,
                           template_name='registration/password_reset_confirm.html',
                           token_generator=default_token_generator,
                           set_password_form=SetPasswordForm,
                           post_reset_redirect=None,
                           current_app=None, extra_context=None):
    """
    View that checks the hash in a password reset link and presents a
    form for entering a new password.
    """
    warnings.warn("The function-based views in django.contrib.auth are deprecated. "
        "Use the class-based ones instead.", stacklevel=2)
    UserModel = get_user_model()
    assert uidb36 is not None and token is not None  # checked by URLconf
    if post_reset_redirect is None:
        post_reset_redirect = reverse('password_reset_complete')
    else:
        post_reset_redirect = resolve_url(post_reset_redirect)
    try:
        uid_int = base36_to_int(uidb36)
        user = UserModel._default_manager.get(pk=uid_int)
    except (ValueError, OverflowError, UserModel.DoesNotExist):
        user = None

    if user is not None and token_generator.check_token(user, token):
        validlink = True
        if request.method == 'POST':
            form = set_password_form(user, request.POST)
            if form.is_valid():
                form.save()
                return HttpResponseRedirect(post_reset_redirect)
        else:
            form = set_password_form(None)
    else:
        validlink = False
        form = None
    context = {
        'form': form,
        'validlink': validlink,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

def password_reset_complete(request,
                            template_name='registration/password_reset_complete.html',
                            current_app=None, extra_context=None):
    warnings.warn("The function-based views in django.contrib.auth are deprecated. "
        "Use the class-based ones instead.", stacklevel=2)
    context = {
        'login_url': resolve_url(settings.LOGIN_URL)
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

@sensitive_post_parameters()
@csrf_protect
@login_required
def password_change(request,
                    template_name='registration/password_change_form.html',
                    post_change_redirect=None,
                    password_change_form=PasswordChangeForm,
                    current_app=None, extra_context=None):
    warnings.warn("The function-based views in django.contrib.auth are deprecated. "
        "Use the class-based ones instead.", stacklevel=2)
    if post_change_redirect is None:
        post_change_redirect = reverse('password_change_done')
    else:
        post_change_redirect = resolve_url(post_change_redirect)
    if request.method == "POST":
        form = password_change_form(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(post_change_redirect)
    else:
        form = password_change_form(user=request.user)
    context = {
        'form': form,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

@login_required
def password_change_done(request,
                         template_name='registration/password_change_done.html',
                         current_app=None, extra_context=None):
    warnings.warn("The function-based views in django.contrib.auth are deprecated. "
        "Use the class-based ones instead.", stacklevel=2)
    context = {}
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)
