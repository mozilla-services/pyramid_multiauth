# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Pyramid authn policy that ties together multiple backends.
"""

import sys
import warnings

from pyramid.authorization import ACLHelper, Authenticated, Everyone
from pyramid.interfaces import (
    PHASE2_CONFIG,
    IAuthenticationPolicy,
    IAuthorizationPolicy,
    ISecurityPolicy,
)
from pyramid.security import LegacySecurityPolicy
from zope.interface import implementer


__ver_major__ = 0
__ver_minor__ = 9
__ver_patch__ = 0
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


if sys.version_info > (3,):  # pragma: nocover
    basestring = str


class MultiAuthPolicySelected(object):
    """Event for tracking which authentication policy was used.

    This event is fired whenever a particular backend policy is successfully
    used for authentication.  It can be used by other parts of the code in
    order to act based on the selected policy::

        from pyramid.events import subscriber

        @subscriber(MultiAuthPolicySelected)
        def track_policy(event):
            print("We selected policy %s" % event.policy)

    """

    def __init__(self, policy, request, userid=None):
        self.policy = policy
        self.policy_name = getattr(policy, "_pyramid_multiauth_name", None)
        self.request = request
        self.userid = userid


class MultiAuthIdentity:
    """Identity for an authenticated user from the sub-policy stack.

    Only created when a userid is found. Extra principals from sub-policies
    that don't authenticate a user (e.g. IP-based) are handled separately
    in ``permits()``.
    """

    def __init__(self, userid: str, groups: list[str] | None):
        """
        :param userid: Authenticated userid string.
        :param groups:  list of groups from the groupfinder callback, or [].
        """
        self.userid = userid
        self.groups = list(groups) if groups else []


@implementer(IAuthenticationPolicy)
class MultiAuthenticationPolicy(object):
    """Pyramid authentication policy for stacked authentication.

    This is a pyramid authentication policy that stitches together other
    authentication policies into a flexible auth stack.  You give it a
    list of IAuthenticationPolicy objects, and it will try each one in
    turn until it obtains a usable response:

        * authenticated_userid:    return userid from first successful policy
        * unauthenticated_userid:  return userid from first successful policy
        * effective_principals:    return union of principals from all policies
        * remember:                return headers from all policies
        * forget:                  return headers from all policies

    """

    def __init__(self, policies, callback=None):
        warnings.warn(
            "MultiAuthenticationPolicy is deprecated. Use MultiAuthSecurityPolicy "
            "and config.set_security_policy() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._policies = policies
        self._callback = callback

    def authenticated_userid(self, request):
        """Find the authenticated userid for this request.

        This method delegates to each authn policy in turn, taking the
        userid from the first one that doesn't return None.  If a
        groupfinder callback is configured, it is also used to validate
        the userid before returning.
        """
        userid = None
        for policy in self._policies:
            userid = policy.authenticated_userid(request)
            if userid is not None:
                request.registry.notify(MultiAuthPolicySelected(policy, request, userid))

                if self._callback is None:
                    break
                if self._callback(userid, request) is not None:
                    break
                else:
                    userid = None
        return userid

    def unauthenticated_userid(self, request):
        """Find the unauthenticated userid for this request.

        This method delegates to each authn policy in turn, taking the
        userid from the first one that doesn't return None.
        """
        userid = None
        for policy in self._policies:
            userid = policy.unauthenticated_userid(request)
            if userid is not None:
                break
        return userid

    def effective_principals(self, request):
        """Get the list of effective principals for this request.

        This method returns the union of the principals returned by each
        authn policy.  If a groupfinder callback is registered, its output
        is also added to the list.
        """
        principals = set((Everyone,))
        for policy in self._policies:
            principals.update(policy.effective_principals(request))
        if self._callback is not None:
            principals.discard(Authenticated)
            groups = None
            for policy in self._policies:
                userid = policy.authenticated_userid(request)
                if userid is None:
                    continue
                request.registry.notify(MultiAuthPolicySelected(policy, request, userid))
                groups = self._callback(userid, request)
                if groups is not None:
                    break
            if groups is not None:
                principals.add(userid)
                principals.add(Authenticated)
                principals.update(groups)
        return list(principals)

    def remember(self, request, principal, **kw):
        """Remember the authenticated userid.

        This method returns the concatenation of the headers returned by each
        authn policy.
        """
        headers = []
        for policy in self._policies:
            headers.extend(policy.remember(request, principal, **kw))
        return headers

    def forget(self, request):
        """Forget a previously remembered userid.

        This method returns the concatenation of the headers returned by each
        authn policy.
        """
        headers = []
        for policy in self._policies:
            headers.extend(policy.forget(request))
        return headers

    def get_policies(self):
        """Get the list of contained authentication policies, as tuple of
        name and instances.

        This may be useful to introspect the configured policies, and their
        respective name defined in configuration.
        """
        return [
            (getattr(policy, "_pyramid_multiauth_name", None), policy) for policy in self._policies
        ]

    def get_policy(self, name_or_class):
        """Get one of the contained authentication policies, by name or class.

        This method can be used to obtain one of the subpolicies loaded
        by this policy object.  The policy can be looked up either by the
        name given to it in the config settings, or or by its class.  If
        no policy is found matching the given query, None is returned.

        This may be useful if you need to access non-standard methods or
        properties on one of the loaded policy objects.
        """
        for policy in self._policies:
            if isinstance(name_or_class, basestring):
                policy_name = getattr(policy, "_pyramid_multiauth_name", None)
                if policy_name == name_or_class:
                    return policy
            else:
                if isinstance(policy, name_or_class):
                    return policy
        return None


@implementer(ISecurityPolicy)
class MultiAuthSecurityPolicy:
    """Pyramid ISecurityPolicy for stacked authentication.

    This is a pyramid security policy that stitches together other
    IAuthenticationPolicy objects into a flexible auth stack, compatible
    with Pyramid 2 security policies.

    https://docs.pylonsproject.org/projects/pyramid/en/latest/narr/security.html#writing-a-security-policy
    """

    # Sentinel to distinguish "no identity yet" from "not authenticated".
    _NO_IDENTITY = object()

    def __init__(self, policies, callback=None, authz_policy=None):
        self._policies = policies
        self._callback = callback
        self._helper = authz_policy if authz_policy is not None else ACLHelper()

    def identity(self, request):
        """Return a ``MultiAuthIdentity`` for the first authenticated userid, or ``None``.

        Iterates sub-policies in order, returning the first ``userid`` that passes
        the optional ``groupfinder`` callback. Fires the ``MultiAuthPolicySelected`` event
        when a policy succeeds.

        The result is cached on the request, since ``permits()`` to avoid expensive
        authentication work (eg. bcrypt, storage hit, JWT, ...) to be performed
        multiple times per request.
        """
        cached = getattr(request, "_multiauth_identity", self._NO_IDENTITY)
        if cached is not self._NO_IDENTITY:
            return cached
        identity = self._compute_identity(request)
        request._multiauth_identity = identity
        return identity

    def _compute_identity(self, request):
        for policy in self._policies:
            userid = policy.authenticated_userid(request)
            if userid is None:
                continue
            # User was authenticated successfully!
            if self._callback is None:
                # No groups.
                request.registry.notify(MultiAuthPolicySelected(policy, request, userid))
                return MultiAuthIdentity(userid, [])

            groups = self._callback(userid, request)
            if groups is not None:
                request.registry.notify(MultiAuthPolicySelected(policy, request, userid))
                return MultiAuthIdentity(userid, groups)
        return None

    def authenticated_userid(self, request):
        identity = self.identity(request)
        return identity.userid if identity is not None else None

    def permits(self, request, context, permission):
        """Check if the request is permitted to perform the action.

        Collects principals from all sub-policies (for non-userid sub-policies
        that only contribute extra principals), then adds the authenticated
        identity's userid and groups if present.
        """
        principals = self._principals(request)
        return self._helper.permits(context, principals, permission)

    def _principals(self, request):
        """Gather (and cache per request) the full set of principals."""
        cached = getattr(request, "_multiauth_principals", self._NO_IDENTITY)
        if cached is not self._NO_IDENTITY:
            return cached

        principals = {Everyone}
        for policy in self._policies:
            for p in policy.effective_principals(request):
                if p not in (Everyone, Authenticated):
                    principals.add(p)

        identity = self.identity(request)
        if identity is not None:
            principals.add(Authenticated)
            principals.add(identity.userid)
            principals.update(identity.groups)
        request._multiauth_principals = principals
        return principals

    def remember(self, request, userid, **kwargs):
        headers = []
        for policy in self._policies:
            headers.extend(policy.remember(request, userid, **kwargs))
        return headers

    def forget(self, request, **kwargs):
        headers = []
        for policy in self._policies:
            # **kwargs not forwarded: old IAuthenticationPolicy.forget() has no **kwargs
            headers.extend(policy.forget(request))
        return headers

    def get_policies(self):
        """Get the list of contained authentication policies, as tuple of
        name and instances.
        """
        return [
            (getattr(policy, "_pyramid_multiauth_name", None), policy) for policy in self._policies
        ]

    def get_policy(self, name_or_class):
        """Get one of the contained authentication policies, by name or class."""
        for policy in self._policies:
            if isinstance(name_or_class, basestring):
                policy_name = getattr(policy, "_pyramid_multiauth_name", None)
                if policy_name == name_or_class:
                    return policy
            else:
                if isinstance(policy, name_or_class):
                    return policy
        return None


def includeme(config):
    """Include pyramid_multiauth into a pyramid configurator.

    This function provides a hook for pyramid to include the default settings
    for auth via pyramid_multiauth.  Activate it like so:

        config.include("pyramid_multiauth")

    This will pull the list of registered authn policies from the deployment
    settings, and configure and install each policy in order.  The policies to
    use can be specified in one of two ways:

        * as the name of a module to be included.
        * as the name of a callable along with a set of parameters.

    Here's an example suite of settings:

        multiauth.policies = ipauth1 ipauth2 pyramid_browserid

        multiauth.policy.ipauth1.use = pyramid_ipauth.IPAuthentictionPolicy
        multiauth.policy.ipauth1.ipaddrs = 123.123.0.0/16
        multiauth.policy.ipauth1.userid = local1

        multiauth.policy.ipauth2.use = pyramid_ipauth.IPAuthentictionPolicy
        multiauth.policy.ipauth2.ipaddrs = 124.124.0.0/16
        multiauth.policy.ipauth2.userid = local2

    This will configure a MultiAuthSecurityPolicy with three policy objects.
    The first two will be IPAuthenticationPolicy objects created by passing
    in the specified keyword arguments.  The third will be a BrowserID
    authentication policy just like you would get from executing:

        config.include("pyramid_browserid")

    As a side-effect, the configuration will also get the additional views
    that pyramid_browserid sets up by default.

    The *group finder function* and the *authorization policy* are also read
    from configuration if specified:

        multiauth.authorization_policy = mypyramidapp.acl.Custom
        multiauth.groupfinder  = mypyramidapp.acl.groupfinder
    """
    # Grab the pyramid-wide settings, to look for any auth config.
    settings = config.get_settings()
    # Hook up a default AuthorizationPolicy.
    # Get the authorization policy from config if present.
    # Default ACLAuthorizationPolicy is usually what you want.
    authz_class = settings.get(
        "multiauth.authorization_policy", "pyramid.authorization.ACLAuthorizationPolicy"
    )
    authz_policy = config.maybe_dotted(authz_class)()
    # We register an IAuthorizationPolicy like in Pyramid 1.X. for backward compat
    # because some authentication policies may still query it.
    # We use ``registerUtility()`` instead of ``config.set_authorization_policy()``
    # to avoid deprecation warnings.
    config.registry.registerUtility(authz_policy, IAuthorizationPolicy)
    # Get the groupfinder from config if present.
    groupfinder = settings.get("multiauth.groupfinder", None)
    groupfinder = config.maybe_dotted(groupfinder)
    # Look for callable policy definitions.
    # Suck them all out at once and store them in a dict for later use.
    policy_definitions = get_policy_definitions(settings)
    # Read and process the list of policies to load.
    # We build up a list of callables which can be executed at config commit
    # time to obtain the final list of policies.
    # Yeah, it's complicated.  But we want to be able to inherit any default
    # views or other config added by the sub-policies when they're included.
    # Process policies in reverse order so that things at the front of the
    # list can override things at the back of the list.
    policy_factories = []
    policy_names = settings.get("multiauth.policies", "").split()
    for policy_name in reversed(policy_names):
        if policy_name in policy_definitions:
            # It's a policy defined using a callable.
            # Just append it straight to the list.
            definition = policy_definitions[policy_name]
            factory = config.maybe_dotted(definition.pop("use"))
            policy_factories.append((factory, policy_name, definition))
        else:
            # It's a module to be directly included.
            try:
                factory = policy_factory_from_module(config, policy_name)
            except ImportError:
                err = "pyramid_multiauth: policy %r has no settings and is not importable" % (
                    policy_name,
                )
                raise ValueError(err)
            policy_factories.append((factory, policy_name, {}))
    # OK.  We now have a list of callbacks which need to be called at
    # commit time, and will return the policies in reverse order.
    # Register a special action to pull them into our list of policies.
    policies = []

    def grab_policies():
        for factory, name, kwds in policy_factories:
            policy = factory(**kwds)
            if policy:
                policy._pyramid_multiauth_name = name
                if not policies or policy is not policies[0]:
                    # Remember, they're being processed in reverse order.
                    # So each new policy needs to go at the front.
                    policies.insert(0, policy)

    config.action(None, grab_policies, order=PHASE2_CONFIG)

    # We register an IAuthenticationPolicy like in Pyramid 1.X. so that deferred actions
    # of include() calls are suppressed via Pyramid's conflict resolution.
    # Without this, those actions fire alongside our ISecurityPolicy registration
    # and raise a ConfigurationError ("Cannot configure an authentication policy...
    # with a configured security policy").
    config.action(IAuthenticationPolicy, lambda: None, order=PHASE2_CONFIG)

    # Now we set the main security policy of Pyramid 2.
    security_policy = MultiAuthSecurityPolicy(policies, groupfinder, authz_policy)
    config.set_security_policy(security_policy)


def policy_factory_from_module(config, module):
    """Create a policy factory that works by config.include()'ing a module.

    This function does some trickery with the Pyramid config system. Loosely,
    it does config.include(module), and then sucks out information about the
    authn policy that was registered.  It's complicated by pyramid's delayed-
    commit system, which means we have to do the work via callbacks.
    """
    # Remember the policy that's active before including the module, if any.
    orig_policy = config.registry.queryUtility(IAuthenticationPolicy)
    # Include the module, so we get any default views etc.
    config.include(module)
    # That might have registered and commited a new policy object.
    policy = config.registry.queryUtility(IAuthenticationPolicy)
    if policy is not None and policy is not orig_policy:
        # The module called config.commit() internally. Clean up: restore the
        # original ``IAuthenticationPolicy``
        config.registry.registerUtility(orig_policy, IAuthenticationPolicy)
        # And any ```LegacySecurityPolicy`` side-effect that Pyramid did.
        # (We manage both ourselves via ``MultiAuthSecurityPolicy``)
        security = config.registry.queryUtility(ISecurityPolicy)
        if isinstance(security, LegacySecurityPolicy):
            config.registry.registerUtility(None, ISecurityPolicy)
        return lambda: policy
    # Or it might have set up a pending action to register one later.
    # Find the most recent IAuthenticationPolicy action, and grab
    # out the registering function so we can call it ourselves.
    for action in reversed(config.action_state.actions):
        # Extract the discriminator and callable.
        discriminator = action["discriminator"]
        callable = action["callable"]
        # If it's not setting the authn policy, keep looking.
        if discriminator is not IAuthenticationPolicy:
            continue

        # Otherwise, wrap it up so we can extract the registered object.
        def grab_policy(register=callable):
            # In Pyramid 2.0, a default security policy is registered when
            # none is found:
            # https://github.com/Pylons/pyramid/blob/8061fce/src/pyramid/config/security.py#L100-L101
            # When including various policies, this can result in
            # `ConfigurationError`s since we're not supposed to set
            # authentication once a security policy is already in place.
            # Clean-up this side-effect manually here.
            security = config.registry.queryUtility(ISecurityPolicy)
            if isinstance(security, LegacySecurityPolicy):
                config.registry.registerUtility(None, ISecurityPolicy)

            old_policy = config.registry.queryUtility(IAuthenticationPolicy)
            register()
            new_policy = config.registry.queryUtility(IAuthenticationPolicy)
            config.registry.registerUtility(old_policy, IAuthenticationPolicy)

            # Clean-up the side-effect of the default security policy
            # here too, after executing the actions via `register()`.
            security = config.registry.queryUtility(ISecurityPolicy)
            if isinstance(security, LegacySecurityPolicy):
                config.registry.registerUtility(None, ISecurityPolicy)

            return new_policy

        return grab_policy
    # Or it might not have done *anything*.
    # So return a null policy factory.
    return lambda: None


def get_policy_definitions(settings):
    """Find all multiauth policy definitions from the settings dict.

    This function processes the paster deployment settings looking for items
    that start with "multiauth.policy.<policyname>.".  It pulls them all out
    into a dict indexed by the policy name.
    """
    policy_definitions = {}
    for name in settings:
        if not name.startswith("multiauth.policy."):
            continue
        value = settings[name]
        name = name[len("multiauth.policy.") :]
        policy_name, setting_name = name.split(".", 1)
        if policy_name not in policy_definitions:
            policy_definitions[policy_name] = {}
        policy_definitions[policy_name][setting_name] = value
    return policy_definitions
