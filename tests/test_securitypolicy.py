# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

import pyramid.testing
from pyramid.authorization import ACLAuthorizationPolicy, Allow, Authenticated, Everyone
from pyramid.interfaces import IAuthenticationPolicy, ISecurityPolicy
from pyramid.testing import DummyRequest, testConfig

from pyramid_multiauth import MultiAuthIdentity, MultiAuthPolicySelected, MultiAuthSecurityPolicy

from .support import (
    AuthnPolicy1,
    AuthnPolicy2,
    AuthnPolicy3,
    AuthzPolicyAlwaysPermits,
    customgroupfinder,
)


class DummyContext:
    def __init__(self, acl=None):
        if acl is not None:
            self.__acl__ = acl


class MultiAuthSecurityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = pyramid.testing.setUp(autocommit=False)

    def tearDown(self):
        pyramid.testing.tearDown()

    def test_identity_anonymous(self):
        policy = MultiAuthSecurityPolicy([])
        request = DummyRequest()
        self.assertIsNone(policy.identity(request))

    def test_identity_extra_principals_only(self):
        # AuthnPolicy1 adds "test1" to principals but has no authenticated userid.
        policy = MultiAuthSecurityPolicy([AuthnPolicy1()])
        request = DummyRequest()
        self.assertIsNone(policy.identity(request))

    def test_identity_with_userid(self):
        policy = MultiAuthSecurityPolicy([AuthnPolicy2()])
        request = DummyRequest()
        identity = policy.identity(request)
        self.assertIsNotNone(identity)
        self.assertIsInstance(identity, MultiAuthIdentity)
        self.assertEqual(identity.userid, "test2")
        self.assertEqual(identity.groups, [])

    def test_identity_with_groupfinder(self):
        # customgroupfinder only recognizes "test3".
        policy = MultiAuthSecurityPolicy(
            [AuthnPolicy2(), AuthnPolicy3()], callback=customgroupfinder
        )
        request = DummyRequest()
        identity = policy.identity(request)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.userid, "test3")
        self.assertEqual(identity.groups, ["group"])

    def test_identity_none_if_groupfinder_returns_none(self):
        # customgroupfinder only recognizes "test3".
        policy = MultiAuthSecurityPolicy([AuthnPolicy2()], callback=customgroupfinder)
        request = DummyRequest()
        self.assertIsNone(policy.identity(request))

    def test_identity_fires_event(self):
        policies = [AuthnPolicy2()]
        policy = MultiAuthSecurityPolicy(policies)
        policies[0]._pyramid_multiauth_name = "policy1"

        with testConfig() as config:
            request = DummyRequest()
            selected = []
            config.add_subscriber(lambda e: selected.append(e), MultiAuthPolicySelected)
            policy.identity(request)

        self.assertEqual(len(selected), 1)
        self.assertIs(selected[0].policy, policies[0])
        self.assertEqual(selected[0].policy_name, "policy1")
        self.assertEqual(selected[0].userid, "test2")
        self.assertIs(selected[0].request, request)

    def test_identity_is_cached_per_request(self):
        calls = []

        class CountingPolicy(AuthnPolicy2):
            def authenticated_userid(self, request):
                calls.append(request)
                return super().authenticated_userid(request)

        policy = MultiAuthSecurityPolicy([CountingPolicy()])
        context = DummyContext(acl=[])
        request = DummyRequest()
        # Repeated authz checks on the same request must not recompute.
        policy.permits(request, context, "view")
        policy.permits(request, context, "view")
        policy.identity(request)
        self.assertEqual(len(calls), 2)
        # A fresh request recomputes from scratch.
        policy.permits(DummyRequest(), context, "view")
        self.assertEqual(len(calls), 4)

    def test_authenticated_userid(self):
        policy = MultiAuthSecurityPolicy([AuthnPolicy2()])
        request = DummyRequest()
        self.assertEqual(policy.authenticated_userid(request), "test2")

        policy_anon = MultiAuthSecurityPolicy([AuthnPolicy1()])
        self.assertIsNone(policy_anon.authenticated_userid(DummyRequest()))

    def test_permits_allows_everyone(self):
        context = DummyContext(acl=[(Allow, Everyone, "view")])
        request = DummyRequest()
        policy = MultiAuthSecurityPolicy([], authz_policy=ACLAuthorizationPolicy())
        self.assertTrue(policy.permits(request, context, "view"))

    def test_permits_allows_authenticated_only(self):
        context = DummyContext(acl=[(Allow, Authenticated, "view")])
        request = DummyRequest()
        policy = MultiAuthSecurityPolicy([], authz_policy=ACLAuthorizationPolicy())
        self.assertFalse(policy.permits(request, context, "view"))

    def test_permits_allows_authenticated(self):
        # AuthnPolicy2 has "test3" as userid
        context = DummyContext(acl=[(Allow, "test2", "edit")])
        request = DummyRequest()
        policy = MultiAuthSecurityPolicy([AuthnPolicy2()], authz_policy=ACLAuthorizationPolicy())
        self.assertTrue(policy.permits(request, context, "edit"))

    def test_permits_with_groups(self):
        # AuthnPolicy3 has "test3" as userid
        # customgroupfinder returns ["group"]
        context = DummyContext(acl=[(Allow, "group", "admin")])
        request = DummyRequest()
        policy = MultiAuthSecurityPolicy(
            [AuthnPolicy3()],
            callback=customgroupfinder,
            authz_policy=ACLAuthorizationPolicy(),
        )
        self.assertTrue(policy.permits(request, context, "admin"))

    def test_permits_extra_principals(self):
        # AuthnPolicy1 adds "test1" to principals but has no userid.
        # The principal should still be collected in permits() and allow access.
        context = DummyContext(acl=[(Allow, "test1", "view")])
        request = DummyRequest()
        policy = MultiAuthSecurityPolicy([AuthnPolicy1()], authz_policy=ACLAuthorizationPolicy())
        self.assertTrue(policy.permits(request, context, "view"))

    def test_permits_custom_authz(self):
        context = DummyContext()
        request = DummyRequest()
        policy = MultiAuthSecurityPolicy([], authz_policy=AuthzPolicyAlwaysPermits())
        self.assertTrue(policy.permits(request, context, "anything"))

    def test_remember_and_forget(self):
        policies = [AuthnPolicy1(), AuthnPolicy2(), AuthnPolicy3()]
        policy = MultiAuthSecurityPolicy(policies)
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

    def test_get_policy_by_name(self):
        p1 = AuthnPolicy1()
        p2 = AuthnPolicy2()
        p1._pyramid_multiauth_name = "policy1"
        p2._pyramid_multiauth_name = "policy2"
        policy = MultiAuthSecurityPolicy([p1, p2])
        self.assertIs(policy.get_policy("policy1"), p1)
        self.assertIs(policy.get_policy("policy2"), p2)
        self.assertIsNone(policy.get_policy("policy3"))

    def test_get_policy_by_class(self):
        p1 = AuthnPolicy1()
        p2 = AuthnPolicy2()
        policy = MultiAuthSecurityPolicy([p1, p2])
        self.assertIsInstance(policy.get_policy(AuthnPolicy1), AuthnPolicy1)
        self.assertIsInstance(policy.get_policy(AuthnPolicy2), AuthnPolicy2)
        self.assertIsNone(policy.get_policy(AuthnPolicy3))

    def test_get_policies(self):
        p1 = AuthnPolicy1()
        p2 = AuthnPolicy2()
        p1._pyramid_multiauth_name = "policy1"
        p2._pyramid_multiauth_name = "policy2"
        policy = MultiAuthSecurityPolicy([p1, p2])
        policies = policy.get_policies()
        self.assertEqual(len(policies), 2)
        self.assertEqual(policies[0], ("policy1", p1))
        self.assertEqual(policies[1], ("policy2", p2))

    def test_includeme_sets_security_policy(self):
        self.config.add_settings(
            {
                "multiauth.groupfinder": "tests.support.customgroupfinder",
                "multiauth.policies": "tests.support.includeme2",
            }
        )
        self.config.include("pyramid_multiauth")
        self.config.commit()
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(security, MultiAuthSecurityPolicy)
        self.assertEqual(security._callback, customgroupfinder)
        self.assertEqual(len(security._policies), 1)

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
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(security, MultiAuthSecurityPolicy)
        self.assertEqual(security._callback, customgroupfinder)
        self.assertEqual(len(security._policies), 3)
        request = DummyRequest()
        self.assertEqual(security.authenticated_userid(request), "test3")

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
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(security, MultiAuthSecurityPolicy)
        self.assertEqual(security._callback, customgroupfinder)
        self.assertEqual(len(security._policies), 3)
        self.assertEqual(security._policies[1].foo, "bar")
        request = DummyRequest()
        self.assertEqual(security.authenticated_userid(request), "test3")

    def test_includeme_by_module_leaves_registry_clean(self):
        # Regression test for the conflict-resolution machinery.
        # includeme1/includeme2 register via config.set_authentication_policy()
        # (deferred-action path, like kinto.core.authentication)
        # includeme3 calls config.commit() (committed path)
        # Both must be suppressed so that our set_security_policy()
        # does not raise ConfigurationError and no LegacySecurityPolicy side-effect lingers.
        from pyramid.security import LegacySecurityPolicy

        self.config.add_settings(
            {
                "multiauth.policies": "tests.support.includeme1 "
                "tests.support.includeme2 "
                "tests.support.includeme3 ",
            }
        )
        # Must not raise ConfigurationError.
        self.config.include("pyramid_multiauth")
        self.config.commit()
        # The security policy is ours, not a leftover LegacySecurityPolicy.
        security = self.config.registry.getUtility(ISecurityPolicy)
        self.assertIsInstance(security, MultiAuthSecurityPolicy)
        self.assertNotIsInstance(security, LegacySecurityPolicy)
        # The sub-modules' IAuthenticationPolicy registrations were suppressed.
        self.assertIsNone(self.config.registry.queryUtility(IAuthenticationPolicy))
