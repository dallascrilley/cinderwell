"""Matchbox: disposable cloud dev servers that destroy themselves on a lease.

Six modules, in the order a host moves through them:

* ``paths``      -- machine-scoped config and state locations (XDG)
* ``lifecycle``  -- read-only planning, pricing, leases, authority, receipts
* ``approve``    -- write an approval naming one plan's exact hash
* ``provision``  -- apply an approved plan; abort a half-created host
* ``teardown``   -- destroy a host and prove absence by re-reading the provider
* ``reaper``     -- enforce the lease on a schedule, preserving work first

Schemas and templates ship as package data under ``cinderwell.resources`` and
are resolved through importlib.resources -- never by walking from ``__file__``
to a repository root, because the reaper outlives any one checkout.
"""

__version__ = "0.1.0"
