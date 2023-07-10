
from django.http import HttpResponseRedirect
from django.conf import settings
from re import compile

# login not required on 'static/.*' to allow png and css on the login page
# (js access is prohibited until login is done in the view)
EXEMPT_URLS = [compile(settings.LOGIN_URL.lstrip('/')), compile('rest/.*'), compile('static/(?!doc).*'), compile('saml2/.*')]
if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
    EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]


class LoginRequiredMiddleware(object):
    """
    Middleware that requires a user to be authenticated to view any page other
    than LOGIN_URL. Exemptions to this requirement can optionally be specified
    in settings via a list of regular expressions in LOGIN_EXEMPT_URLS (which
    you can copy from your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in EXEMPT_URLS):
                return HttpResponseRedirect(settings.LOGIN_URL + path)

        return self.get_response(request)
