from pyramid.authorization import Authenticated, Everyone
from pyramid.exceptions import Forbidden
from pyramid.interfaces import IAuthenticationPolicy, IAuthorizationPolicy
from zope.interface import implementer


@implementer(IAuthenticationPolicy)
class BaseAuthnPolicy(object):
    """A do-nothing base class for authn policies."""

    def __init__(self, **kwds):
        self.__dict__.update(kwds)

    def authenticated_userid(self, request):
        return self.unauthenticated_userid(request)

    def unauthenticated_userid(self, request):
        return None

    def effective_principals(self, request):
        principals = [Everyone]
        userid = self.authenticated_userid(request)
        if userid is not None:
            principals.append(Authenticated)
            principals.append(userid)
        return principals

    def remember(self, request, principal):
        return []

    def forget(self, request):
        return []


@implementer(IAuthenticationPolicy)
class AuthnPolicy1(BaseAuthnPolicy):
    """An authn policy that adds "test1" to the principals."""

    def effective_principals(self, request):
        return [Everyone, "test1"]

    def remember(self, request, principal):
        return [("X-Remember", principal)]

    def forget(self, request):
        return [("X-Forget", "foo")]


@implementer(IAuthenticationPolicy)
class AuthnPolicy2(BaseAuthnPolicy):
    """An authn policy that sets "test2" as the username."""

    def unauthenticated_userid(self, request):
        return "test2"

    def remember(self, request, principal):
        return [("X-Remember-2", principal)]

    def forget(self, request):
        return [("X-Forget", "bar")]


@implementer(IAuthenticationPolicy)
class AuthnPolicy3(BaseAuthnPolicy):
    """Authn policy that sets "test3" as the username "test4" in principals."""

    def unauthenticated_userid(self, request):
        return "test3"

    def effective_principals(self, request):
        return [Everyone, Authenticated, "test3", "test4"]


@implementer(IAuthenticationPolicy)
class AuthnPolicyUnauthOnly(BaseAuthnPolicy):
    """An authn policy that returns an unauthenticated userid but not an
    authenticated userid, similar to the basic auth policy.
    """

    def authenticated_userid(self, request):
        return None

    def unauthenticated_userid(self, request):
        return "test3"

    def effective_principals(self, request):
        return [Everyone]


@implementer(IAuthorizationPolicy)
class AuthzPolicyAlwaysPermits(object):
    def permits(self, context, principals, permission):
        return True

    def principals_allowed_by_permission(self, context, permission):
        raise NotImplementedError()  # pragma: nocover


def includeme1(config):
    """Config include that sets up a AuthnPolicy1 and a forbidden view."""
    config.set_authentication_policy(AuthnPolicy1())

    def forbidden_view(request):
        return "FORBIDDEN ONE"

    config.add_view(forbidden_view, renderer="json", context="pyramid.exceptions.Forbidden")


def includeme2(config):
    """Config include that sets up a AuthnPolicy2."""
    config.set_authentication_policy(AuthnPolicy2())


def includemenull(config):
    """Config include that doesn't do anything."""
    pass


def includeme3(config):
    """Config include that adds a TestAuthPolicy3 and commits it."""
    config.set_authentication_policy(AuthnPolicy3())
    config.commit()


def raiseforbidden(request):
    """View that always just raises Forbidden."""
    raise Forbidden()


def customgroupfinder(userid, request):
    """A test groupfinder that only recognizes user "test3"."""
    if userid != "test3":
        return None
    return ["group"]
