# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

import pyramid.testing
from pyramid.authorization import ACLAuthorizationPolicy, Authenticated, Everyone
from pyramid.exceptions import Forbidden
from pyramid.interfaces import IAuthenticationPolicy, IAuthorizationPolicy, ISecurityPolicy
from pyramid.security import LegacySecurityPolicy
from pyramid.testing import DummyRequest
from pyramid_multiauth import MultiAuthenticationPolicy
from zope.interface import implementer


#  Here begins various helper classes and functions for the tests.


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
class TestAuthnPolicy1(BaseAuthnPolicy):
    """An authn policy that adds "test1" to the principals."""

    def effective_principals(self, request):
        return [Everyone, "test1"]

    def remember(self, request, principal):
        return [("X-Remember", principal)]

    def forget(self, request):
        return [("X-Forget", "foo")]


@implementer(IAuthenticationPolicy)
class TestAuthnPolicy2(BaseAuthnPolicy):
    """An authn policy that sets "test2" as the username."""

    def unauthenticated_userid(self, request):
        return "test2"

    def remember(self, request, principal):
        return [("X-Remember-2", principal)]

    def forget(self, request):
        return [("X-Forget", "bar")]


@implementer(IAuthenticationPolicy)
class TestAuthnPolicy3(BaseAuthnPolicy):
    """Authn policy that sets "test3" as the username "test4" in principals."""

    def unauthenticated_userid(self, request):
        return "test3"

    def effective_principals(self, request):
        return [Everyone, Authenticated, "test3", "test4"]


@implementer(IAuthenticationPolicy)
class TestAuthnPolicyUnauthOnly(BaseAuthnPolicy):
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
class TestAuthzPolicyCustom(object):
    def permits(self, context, principals, permission):
        return True

    def principals_allowed_by_permission(self, context, permission):
        raise NotImplementedError()  # pragma: nocover


def includeme1(config):
    """Config include that sets up a TestAuthnPolicy1 and a forbidden view."""
    config.set_authentication_policy(TestAuthnPolicy1())

    def forbidden_view(request):
        return "FORBIDDEN ONE"

    config.add_view(forbidden_view, renderer="json", context="pyramid.exceptions.Forbidden")


def includeme2(config):
    """Config include that sets up a TestAuthnPolicy2."""
    config.set_authentication_policy(TestAuthnPolicy2())


def includemenull(config):
    """Config include that doesn't do anything."""
    pass


def includeme3(config):
    """Config include that adds a TestAuthPolicy3 and commits it."""
    config.set_authentication_policy(TestAuthnPolicy3())
    config.commit()


def raiseforbidden(request):
    """View that always just raises Forbidden."""
    raise Forbidden()


def customgroupfinder(userid, request):
    """A test groupfinder that only recognizes user "test3"."""
    if userid != "test3":
        return None
    return ["group"]


#  Here begins the actual test cases


class MultiAuthPolicyTests(unittest.TestCase):
    """Testcases for MultiAuthenticationPolicy and related hooks."""

    def setUp(self):
        self.config = pyramid.testing.setUp(autocommit=False)

    def tearDown(self):
        pyramid.testing.tearDown()

    def test_basic_stacking(self):
        policies = [TestAuthnPolicy1(), TestAuthnPolicy2()]
        policy = MultiAuthenticationPolicy(policies)
        request = DummyRequest()
        self.assertEqual(policy.authenticated_userid(request), "test2")
        self.assertEqual(
            sorted(policy.effective_principals(request)),
            [Authenticated, Everyone, "test1", "test2"],
        )

    def test_policy_selected_event(self):
        from pyramid.testing import testConfig
        from pyramid_multiauth import MultiAuthPolicySelected

        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies)
        # Simulate loading from config:
        policies[0]._pyramid_multiauth_name = "name"

        with testConfig() as config:
            request = DummyRequest()

            selected_policy = []

            def track_policy(event):
                selected_policy.append(event)

            config.add_subscriber(track_policy, MultiAuthPolicySelected)

            self.assertEqual(policy.authenticated_userid(request), "test2")

            self.assertEqual(selected_policy[0].policy, policies[0])
            self.assertEqual(selected_policy[0].policy_name, "name")
            self.assertEqual(selected_policy[0].userid, "test2")
            self.assertEqual(selected_policy[0].request, request)
            self.assertEqual(len(selected_policy), 1)

            # Effective principals also triggers an event when groupfinder
            # is provided.
            policy_with_group = MultiAuthenticationPolicy(policies, lambda u, r: ["foo"])
            policy_with_group.effective_principals(request)
            self.assertEqual(len(selected_policy), 2)

    def test_stacking_of_unauthenticated_userid(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies)
        request = DummyRequest()
        self.assertEqual(policy.unauthenticated_userid(request), "test2")
        policies.reverse()
        self.assertEqual(policy.unauthenticated_userid(request), "test3")

    def test_stacking_of_authenticated_userid(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies)
        request = DummyRequest()
        self.assertEqual(policy.authenticated_userid(request), "test2")
        policies.reverse()
        self.assertEqual(policy.authenticated_userid(request), "test3")

    def test_stacking_of_authenticated_userid_with_groupdfinder(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies, customgroupfinder)
        request = DummyRequest()
        self.assertEqual(policy.authenticated_userid(request), "test3")
        policies.reverse()
        self.assertEqual(policy.unauthenticated_userid(request), "test3")

    def test_only_unauthenticated_userid_with_groupfinder(self):
        policies = [TestAuthnPolicyUnauthOnly()]
        policy = MultiAuthenticationPolicy(policies, customgroupfinder)
        request = DummyRequest()
        self.assertEqual(policy.unauthenticated_userid(request), "test3")
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertEqual(policy.effective_principals(request), [Everyone])

    def test_authenticated_userid_unauthenticated_with_groupfinder(self):
        policies = [TestAuthnPolicy2()]
        policy = MultiAuthenticationPolicy(policies, customgroupfinder)
        request = DummyRequest()
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertEqual(sorted(policy.effective_principals(request)), [Everyone, "test2"])

    def test_stacking_of_effective_principals(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies)
        request = DummyRequest()
        self.assertEqual(
            sorted(policy.effective_principals(request)),
            [Authenticated, Everyone, "test2", "test3", "test4"],
        )
        policies.reverse()
        self.assertEqual(
            sorted(policy.effective_principals(request)),
            [Authenticated, Everyone, "test2", "test3", "test4"],
        )
        policies.append(TestAuthnPolicy1())
        self.assertEqual(
            sorted(policy.effective_principals(request)),
            [Authenticated, Everyone, "test1", "test2", "test3", "test4"],
        )

    def test_stacking_of_effective_principals_with_groupfinder(self):
        policies = [TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies, customgroupfinder)
        request = DummyRequest()
        self.assertEqual(
            sorted(policy.effective_principals(request)),
            ["group", Authenticated, Everyone, "test2", "test3", "test4"],
        )
        policies.reverse()
        self.assertEqual(
            sorted(policy.effective_principals(request)),
            ["group", Authenticated, Everyone, "test2", "test3", "test4"],
        )
        policies.append(TestAuthnPolicy1())
        self.assertEqual(
            sorted(policy.effective_principals(request)),
            ["group", Authenticated, Everyone, "test1", "test2", "test3", "test4"],
        )

    def test_stacking_of_remember_and_forget(self):
        policies = [TestAuthnPolicy1(), TestAuthnPolicy2(), TestAuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies)
        request = DummyRequest()
        self.assertEqual(
            policy.remember(request, "ha"), [("X-Remember", "ha"), ("X-Remember-2", "ha")]
        )
        self.assertEqual(policy.forget(request), [("X-Forget", "foo"), ("X-Forget", "bar")])
        policies.reverse()
        self.assertEqual(
            policy.remember(request, "ha"), [("X-Remember-2", "ha"), ("X-Remember", "ha")]
        )
        self.assertEqual(policy.forget(request), [("X-Forget", "bar"), ("X-Forget", "foo")])

    def test_includeme_uses_acl_authorization_by_default(self):
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthorizationPolicy)
        expected = ACLAuthorizationPolicy
        self.assertTrue(isinstance(policy, expected))

    def test_includeme_reads_authorization_from_settings(self):
        self.config.add_settings(
            {"multiauth.authorization_policy": "tests.test_base.TestAuthzPolicyCustom"}
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthorizationPolicy)
        self.assertTrue(isinstance(policy, TestAuthzPolicyCustom))

    def test_includeme_by_module(self):
        self.config.add_settings(
            {
                "multiauth.groupfinder": "tests.test_base.customgroupfinder",
                "multiauth.policies": "tests.test_base.includeme1 "
                "tests.test_base.includeme2 "
                "tests.test_base.includemenull "
                "tests.test_base.includeme3 ",
            }
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertEqual(policy._callback, customgroupfinder)
        self.assertEqual(len(policy._policies), 3)
        # Check that they stack correctly.
        request = DummyRequest()
        self.assertEqual(policy.unauthenticated_userid(request), "test2")
        self.assertEqual(policy.authenticated_userid(request), "test3")
        # Check that the forbidden view gets invoked.
        self.config.add_route("index", path="/")
        self.config.add_view(raiseforbidden, route_name="index")
        app = self.config.make_wsgi_app()
        environ = {"PATH_INFO": "/", "REQUEST_METHOD": "GET"}

        def start_response(*args):
            pass

        result = b"".join(app(environ, start_response))
        self.assertEqual(result, b'"FORBIDDEN ONE"')

    def test_includeme_by_callable(self):
        self.config.add_settings(
            {
                "multiauth.groupfinder": "tests.test_base.customgroupfinder",
                "multiauth.policies": "tests.test_base.includeme1 policy1 policy2",
                "multiauth.policy.policy1.use": "tests.test_base.TestAuthnPolicy2",
                "multiauth.policy.policy1.foo": "bar",
                "multiauth.policy.policy2.use": "tests.test_base.TestAuthnPolicy3",
            }
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertEqual(policy._callback, customgroupfinder)
        self.assertEqual(len(policy._policies), 3)
        self.assertEqual(policy._policies[1].foo, "bar")
        # Check that they stack correctly.
        request = DummyRequest()
        self.assertEqual(policy.unauthenticated_userid(request), "test2")
        self.assertEqual(policy.authenticated_userid(request), "test3")
        # Check that the forbidden view gets invoked.
        self.config.add_route("index", path="/")
        self.config.add_view(raiseforbidden, route_name="index")
        app = self.config.make_wsgi_app()
        environ = {"PATH_INFO": "/", "REQUEST_METHOD": "GET"}

        def start_response(*args):
            pass

        result = b"".join(app(environ, start_response))
        self.assertEqual(result, b'"FORBIDDEN ONE"')

    def test_includeme_with_unconfigured_policy(self):
        self.config.add_settings(
            {
                "multiauth.groupfinder": "tests.test_base.customgroupfinder",
                "multiauth.policies": "tests.test_base.includeme1 policy1 policy2",
                "multiauth.policy.policy1.use": "tests.test_base.TestAuthnPolicy2",
                "multiauth.policy.policy1.foo": "bar",
            }
        )
        self.assertRaises(ValueError, self.config.include, "pyramid_multiauth")

    def test_get_policy(self):
        self.config.add_settings(
            {
                "multiauth.policies": "tests.test_base.includeme1 policy1 policy2",
                "multiauth.policy.policy1.use": "tests.test_base.TestAuthnPolicy2",
                "multiauth.policy.policy1.foo": "bar",
                "multiauth.policy.policy2.use": "tests.test_base.TestAuthnPolicy3",
            }
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        # Test getting policies by name.
        self.assertTrue(isinstance(policy.get_policy("policy1"), TestAuthnPolicy2))
        self.assertTrue(isinstance(policy.get_policy("policy2"), TestAuthnPolicy3))
        self.assertEqual(policy.get_policy("policy3"), None)
        # Test getting policies by class.
        self.assertTrue(isinstance(policy.get_policy(TestAuthnPolicy1), TestAuthnPolicy1))
        self.assertTrue(isinstance(policy.get_policy(TestAuthnPolicy2), TestAuthnPolicy2))
        self.assertTrue(isinstance(policy.get_policy(TestAuthnPolicy3), TestAuthnPolicy3))
        self.assertEqual(policy.get_policy(MultiAuthPolicyTests), None)

    def test_get_policies(self):
        self.config.add_settings(
            {
                "multiauth.policies": "tests.test_base.includeme1 policy1 policy2",
                "multiauth.policy.policy1.use": "tests.test_base.TestAuthnPolicy2",
                "multiauth.policy.policy2.use": "tests.test_base.TestAuthnPolicy3",
            }
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        policies = policy.get_policies()
        expected_result = [
            ("tests.test_base.includeme1", TestAuthnPolicy1),
            ("policy1", TestAuthnPolicy2),
            ("policy2", TestAuthnPolicy3),
        ]
        for obtained, expected in zip(policies, expected_result):
            self.assertEqual(obtained[0], expected[0])
            self.assertTrue(isinstance(obtained[1], expected[1]))

    def test_default_security(self):
        self.config.add_settings({"multiauth.policies": "tests.test_base.includeme1"})
        self.config.include("pyramid_multiauth")
        self.config.commit()

        authn = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertTrue(isinstance(authn, MultiAuthenticationPolicy), authn)
        authz = self.config.registry.getUtility(IAuthorizationPolicy)
        self.assertTrue(isinstance(authz, ACLAuthorizationPolicy), authz)
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertTrue(isinstance(security, LegacySecurityPolicy), security)

    def test_custom_security(self):
        class CustomSecurity:
            # Fake security class, didn't bother to implement interface.
            pass

        # Use an authentication from module.
        self.config.add_settings({"multiauth.policies": "tests.test_base.includeme1"})
        # Will grab the authentication policy setup during include.
        self.config.include("pyramid_multiauth")
        # Set custom security (will override LegacySecurityPolicy).
        self.config.set_security_policy(CustomSecurity())
        self.config.commit()

        # Check that registered authentication and security are appropriate.
        authn = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertTrue(isinstance(authn, MultiAuthenticationPolicy))
        authz = self.config.registry.getUtility(IAuthorizationPolicy)
        self.assertTrue(isinstance(authz, ACLAuthorizationPolicy), authz)
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertTrue(isinstance(security, CustomSecurity))
