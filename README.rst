=================
pyramid_multiauth
=================

An authentication policy for Pyramid that proxies to a stack of other
authentication policies.


Overview
========

MultiAuthenticationPolicy is a Pyramid authentication that proxies to a
stack of *other* IAuthenticationPolicy objects, to provide a combined auth
solution from individual pieces.  Simply pass it a list of policies that
should be tried in order::


    policies = [
        IPAuthenticationPolicy("127.0.*.*", principals=["local"])
        IPAuthenticationPolicy("192.168.*.*", principals=["trusted"])
    ]
    authn_policy = MultiAuthenticationPolicy(policies)
    config.set_authentication_policy(authn_policy)

This example uses the pyramid_ipauth module to assign effective principals
based on originating IP address of the request.  It combines two such
policies so that requests originating from "127.0.*.*" will have principal
"local" while requests originating from "192.168.*.*" will have principal
"trusted".

In general, the results from the stacked authentication policies are combined
as follows:

    * authenticated_userid:    return userid from first successful policy
    * unauthenticated_userid:  return userid from first successful policy
    * effective_principals:    return union of principals from all policies
    * remember:                return headers from all policies
    * forget:                  return headers from all policies


Deployment Settings
===================

It is also possible to specify the authentication policies as part of your
paste deployment settings.  Consider the following example::

    [app:pyramidapp]
    use = egg:mypyramidapp

    multiauth.policies = ipauth1 ipauth2 pyramid_browserid

    multiauth.policy.ipauth1.use = pyramid_ipauth.IPAuthentictionPolicy
    multiauth.policy.ipauth1.ipaddrs = 127.0.*.*
    multiauth.policy.ipauth1.principals = local

    multiauth.policy.ipauth2.use = pyramid_ipauth.IPAuthentictionPolicy
    multiauth.policy.ipauth2.ipaddrs = 192.168.*.*
    multiauth.policy.ipauth2.principals = trusted

To configure authentication from these settings, simply include the multiauth
module into your configurator::

    config.include("pyramid_multiauth")

In this example you would get a MultiAuthenticationPolicy with three stacked
auth policies.  The first two, ipauth1 and ipauth2, are defined as the name of
of a callable along with a set of keyword arguments.  The third is defined as
the name of a module, pyramid_browserid, which will be procecesed via the
standard config.include() mechanism.

The end result would be a system that authenticates users via BrowserID, and
assigns additional principal identifiers based on the originating IP address
of the request.
