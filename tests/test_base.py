# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

import pyramid.testing
from pyramid.authorization import ACLAuthorizationPolicy, Authenticated, Everyone
from pyramid.interfaces import IAuthenticationPolicy, IAuthorizationPolicy, ISecurityPolicy
from pyramid.testing import DummyRequest

from pyramid_multiauth import MultiAuthenticationPolicy, MultiAuthSecurityPolicy

from .support import (
    AuthnPolicy1,
    AuthnPolicy2,
    AuthnPolicy3,
    AuthnPolicyUnauthOnly,
    AuthzPolicyAlwaysPermits,
    customgroupfinder,
    raiseforbidden,
)


class MultiAuthPolicyTests(unittest.TestCase):
    """Testcases for MultiAuthenticationPolicy and related hooks."""

    def setUp(self):
        self.config = pyramid.testing.setUp(autocommit=False)

    def tearDown(self):
        pyramid.testing.tearDown()

    def test_basic_stacking(self):
        policies = [AuthnPolicy1(), AuthnPolicy2()]
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

        policies = [AuthnPolicy2(), AuthnPolicy3()]
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
        policies = [AuthnPolicy2(), AuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies)
        request = DummyRequest()
        self.assertEqual(policy.unauthenticated_userid(request), "test2")
        policies.reverse()
        self.assertEqual(policy.unauthenticated_userid(request), "test3")

    def test_stacking_of_authenticated_userid(self):
        policies = [AuthnPolicy2(), AuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies)
        request = DummyRequest()
        self.assertEqual(policy.authenticated_userid(request), "test2")
        policies.reverse()
        self.assertEqual(policy.authenticated_userid(request), "test3")

    def test_stacking_of_authenticated_userid_with_groupdfinder(self):
        policies = [AuthnPolicy2(), AuthnPolicy3()]
        policy = MultiAuthenticationPolicy(policies, customgroupfinder)
        request = DummyRequest()
        self.assertEqual(policy.authenticated_userid(request), "test3")
        policies.reverse()
        self.assertEqual(policy.unauthenticated_userid(request), "test3")

    def test_only_unauthenticated_userid_with_groupfinder(self):
        policies = [AuthnPolicyUnauthOnly()]
        policy = MultiAuthenticationPolicy(policies, customgroupfinder)
        request = DummyRequest()
        self.assertEqual(policy.unauthenticated_userid(request), "test3")
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertEqual(policy.effective_principals(request), [Everyone])

    def test_authenticated_userid_unauthenticated_with_groupfinder(self):
        policies = [AuthnPolicy2()]
        policy = MultiAuthenticationPolicy(policies, customgroupfinder)
        request = DummyRequest()
        self.assertEqual(policy.authenticated_userid(request), None)
        self.assertEqual(sorted(policy.effective_principals(request)), [Everyone, "test2"])

    def test_stacking_of_effective_principals(self):
        policies = [AuthnPolicy2(), AuthnPolicy3()]
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
        policies.append(AuthnPolicy1())
        self.assertEqual(
            sorted(policy.effective_principals(request)),
            [Authenticated, Everyone, "test1", "test2", "test3", "test4"],
        )

    def test_stacking_of_effective_principals_with_groupfinder(self):
        policies = [AuthnPolicy2(), AuthnPolicy3()]
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
        policies.append(AuthnPolicy1())
        self.assertEqual(
            sorted(policy.effective_principals(request)),
            ["group", Authenticated, Everyone, "test1", "test2", "test3", "test4"],
        )

    def test_stacking_of_remember_and_forget(self):
        policies = [AuthnPolicy1(), AuthnPolicy2(), AuthnPolicy3()]
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
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(security, MultiAuthSecurityPolicy)
        self.assertIsInstance(security._helper, ACLAuthorizationPolicy)

    def test_includeme_reads_authorization_from_settings(self):
        self.config.add_settings(
            {"multiauth.authorization_policy": "tests.support.AuthzPolicyAlwaysPermits"}
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(security._helper, AuthzPolicyAlwaysPermits)

    def test_includeme_by_module(self):
        self.config.add_settings(
            {
                "multiauth.groupfinder": "tests.support.customgroupfinder",
                "multiauth.policies": "tests.support.includeme1 "
                "tests.support.includeme2 "
                "tests.support.includemenull "
                "tests.support.includeme3 ",
            }
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(policy, MultiAuthSecurityPolicy)
        self.assertEqual(policy._callback, customgroupfinder)
        self.assertEqual(len(policy._policies), 3)
        # Check that they stack correctly.
        request = DummyRequest()
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
                "multiauth.groupfinder": "tests.support.customgroupfinder",
                "multiauth.policies": "tests.support.includeme1 policy1 policy2",
                "multiauth.policy.policy1.use": "tests.support.AuthnPolicy2",
                "multiauth.policy.policy1.foo": "bar",
                "multiauth.policy.policy2.use": "tests.support.AuthnPolicy3",
            }
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(policy, MultiAuthSecurityPolicy)
        self.assertEqual(policy._callback, customgroupfinder)
        self.assertEqual(len(policy._policies), 3)
        self.assertEqual(policy._policies[1].foo, "bar")
        # Check that they stack correctly.
        request = DummyRequest()
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
                "multiauth.groupfinder": "tests.support.customgroupfinder",
                "multiauth.policies": "tests.support.includeme1 policy1 policy2",
                "multiauth.policy.policy1.use": "tests.support.AuthnPolicy2",
                "multiauth.policy.policy1.foo": "bar",
            }
        )
        self.assertRaises(ValueError, self.config.include, "pyramid_multiauth")

    def test_get_policy(self):
        self.config.add_settings(
            {
                "multiauth.policies": "tests.support.includeme1 policy1 policy2",
                "multiauth.policy.policy1.use": "tests.support.AuthnPolicy2",
                "multiauth.policy.policy1.foo": "bar",
                "multiauth.policy.policy2.use": "tests.support.AuthnPolicy3",
            }
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(policy, MultiAuthSecurityPolicy)
        # Test getting policies by name.
        self.assertTrue(isinstance(policy.get_policy("policy1"), AuthnPolicy2))
        self.assertTrue(isinstance(policy.get_policy("policy2"), AuthnPolicy3))
        self.assertEqual(policy.get_policy("policy3"), None)
        # Test getting policies by class.
        self.assertTrue(isinstance(policy.get_policy(AuthnPolicy1), AuthnPolicy1))
        self.assertTrue(isinstance(policy.get_policy(AuthnPolicy2), AuthnPolicy2))
        self.assertTrue(isinstance(policy.get_policy(AuthnPolicy3), AuthnPolicy3))
        self.assertEqual(policy.get_policy(MultiAuthPolicyTests), None)

    def test_get_policies(self):
        self.config.add_settings(
            {
                "multiauth.policies": "tests.support.includeme1 policy1 policy2",
                "multiauth.policy.policy1.use": "tests.support.AuthnPolicy2",
                "multiauth.policy.policy2.use": "tests.support.AuthnPolicy3",
            }
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        policy = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(policy, MultiAuthSecurityPolicy)
        policies = policy.get_policies()
        expected_result = [
            ("tests.support.includeme1", AuthnPolicy1),
            ("policy1", AuthnPolicy2),
            ("policy2", AuthnPolicy3),
        ]
        for obtained, expected in zip(policies, expected_result):
            self.assertEqual(obtained[0], expected[0])
            self.assertTrue(isinstance(obtained[1], expected[1]))

    def test_default_security(self):
        self.config.add_settings({"multiauth.policies": "tests.support.includeme1"})
        self.config.include("pyramid_multiauth")
        self.config.commit()

        # IAuthenticationPolicy is no longer registered (MultiAuthSecurityPolicy takes over).
        authn = self.config.registry.queryUtility(IAuthenticationPolicy)
        self.assertIsNone(authn)
        # IAuthorizationPolicy is still registered for backward compat with sub-policies.
        authz = self.config.registry.getUtility(IAuthorizationPolicy)
        self.assertIsInstance(authz, ACLAuthorizationPolicy)
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(security, MultiAuthSecurityPolicy)

    def test_deprecation_warning(self):
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            MultiAuthenticationPolicy([])
        self.assertEqual(len(w), 1)
        self.assertIs(w[0].category, DeprecationWarning)

    def test_custom_security(self):
        class CustomSecurity:
            # Fake security class, didn't bother to implement interface.
            pass

        # Use an authentication from module.
        self.config.add_settings({"multiauth.policies": "tests.support.includeme1"})
        # Will grab the authentication policy setup during include.
        self.config.include("pyramid_multiauth")
        # Set custom security (will override LegacySecurityPolicy).
        self.config.set_security_policy(CustomSecurity())
        self.config.commit()

        # Check that the custom security policy is registered.
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(security, CustomSecurity)
