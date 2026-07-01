Coverage Report
================

:Source: sssd/src/tests/intg/test_pam_responder.py (pytest, 19 cases)
:User story: PAM responder — smart card / certificate authentication modes (try, require,
   missing-name resolution, service-based allow list), custom password prompts, and
   Kerberos authentication (incl. multi-domain skipping)
:Coverage: partial (3 covered/duplicate, 1 retire, 15 gap; 10/15 gap cases ported, 5 proposed)

:File average score: 61 (Backlog)
:Importance profile: 1 critical, 5 high, 11 medium, 2 low
:Remove now: 4 cases (1 retire, 3 duplicate — see below)
:Ports pending: 0 (see "Implementation status" below — 10 cases ported as real tests, 5 cases
   converted to ``pytest.skip`` proposals pending a framework helper)

Implementation status
----------------------

Ported in `SSSD/sssd#8872 <https://github.com/SSSD/sssd/pull/8872>`_
(branch ``rewrite-test_pam_responder.py``), covering all 10 critical/high/medium cases:

* **Implemented (7 new tests, 10 legacy cases, all passing against real VMs):**

  * ``test_smartcard.py::test_smartcard__wrong_pin_rejected`` (test_sc_auth_wrong_pin)
  * ``test_smartcard.py::test_smartcard__try_cert_auth_falls_back_when_certificate_does_not_match``
    (test_try_sc_auth, test_try_sc_auth_no_map)
  * ``test_smartcard.py::test_smartcard__pam_p11_allowed_services_controls_fallback``
    (test_sc_proxy_password_fallback, test_sc_proxy_no_password_fallback) — parametrized on
    the ``su-l`` PAM service name (``su -`` uses ``su-l``, not ``su``)
  * ``test_smartcard.py::test_smartcard__require_cert_auth_succeeds_with_card`` (test_require_sc_auth)
  * ``test_smartcard.py::test_smartcard__require_cert_auth_fails_without_card`` (test_require_sc_auth_no_cert)
  * ``test_authentication.py::test_authentication__custom_password_prompt``
    (test_password_prompting_config_global, test_password_prompting_config_srv) — per-service
    prompt uses ``prompting/password/su-l``, not ``prompting/password/su``
  * ``test_ldap_krb5.py::test_ldap_krb5__pam_sss_domains_option_skips_non_matching_domains``
    (test_krb5_auth_domains)

* **Proposed only, blocked on a framework gap (``pytest.skip``, 2 stub tests, 5 legacy cases):**

  * ``test_smartcard.py::test_smartcard__root_never_uses_certificate_authentication``
    (test_try_sc_auth_root) — no framework helper originates a fresh PAM auth attempt for
    ``root`` itself (unlike ``su``/``ssh`` as a non-root target user).
  * ``test_smartcard.py::test_smartcard__missing_name_resolves_certificate_owner``
    (test_sc_auth_missing_name, test_sc_auth_missing_name_whitespace, test_sc_auth_name_format,
    test_sc_auth_two_missing_name) — ``allow_missing_name`` is only wired into authselect's
    ``smartcard-auth`` template (login-manager-style services), not ``system-auth``
    (``su``/``sudo``); a console ``login``-driving helper (pexpect over a real TTY) is needed.

**Note:** two PAM service naming gotchas were found and fixed while implementing these tests:
``su -`` (login shell) is served by PAM service **``su-l``**, not ``su`` — both
``pam_p11_allowed_services`` and ``prompting/password/<service>`` needed to target ``su-l`` for
the per-service case to actually take effect.

SSSD configuration
------------------

Verified against man pages (``sssd/src/man/sssd.conf.5.xml`` and ``sssd/src/man/pam_sss.8.xml``):

* ``pam_cert_auth`` (bool) — sssd.conf(5) ``[pam]`` section; enables the PAM responder's
  certificate/smart-card code path at all. Responder-generic — **AnyProvider**.
* ``pam_p11_allowed_services`` (string) — sssd.conf(5) ``[pam]``; comma-separated PAM
  service allow list for smart-card auth, with ``+svc``/``-svc`` add/remove syntax.
  Responder-generic — **AnyProvider**.
* ``p11_child_timeout`` / ``p11_wait_for_card_timeout`` (integer) — sssd.conf(5) ``[pam]``;
  bound how long the responder waits for ``p11_child`` / for a card to be inserted when
  ``require_cert_auth`` is set. Responder-generic — **AnyProvider**. Both are tunable to
  small values (e.g. ``1``) in tests to avoid the legacy suite's real ~20s wait.
* ``p11_uri`` / ``pam_cert_db_path`` (string) — sssd.conf(5) ``[pam]``; reader/token
  selection and trust anchor path. Responder-generic — **AnyProvider**; not behavior under
  test here (fixture plumbing only).
* ``[certmap/<domain>/<rule>]`` section (``matchrule``/``maprule``) — sssd.conf(5); maps a
  certificate to a user. Responder-generic — **AnyProvider**.
* ``try_cert_auth`` / ``require_cert_auth`` / ``allow_missing_name`` — **pam_sss.so PAM
  module options** (``sssd/src/man/pam_sss.8.xml``), not ``sssd.conf`` keys. Set per PAM
  service in ``/etc/pam.d/<service>``, same pattern already used by
  ``test_authentication__user_login_with_modified_PAM_stack_provider_is_offline``
  (``client.fs.write("/etc/pam.d/<service>", ...)``). Module-generic — **AnyProvider**.
* ``[prompting/password]`` / ``[prompting/password/<service>]`` — sssd.conf(5)
  ``password_prompt``; customizes the text of the password prompt, globally or per PAM
  service. Responder-generic — **AnyProvider**.
* ``auth_provider = krb5`` + ``krb5_realm`` / ``krb5_server`` — sssd-krb5(5); standard
  Kerberos auth, already exercised extensively by ``test_ldap_krb5.py`` and
  ``test_authentication.py`` via ``client.sssd.common.krb5_auth(kdc)``.
* Legacy ``id_provider = proxy`` + ``proxy_lib_name = call`` is a **test-harness
  substitute** for a real identity backend (NSS wrapper), not the behavior under test —
  do not port; use ``client.local.user()`` (as ``test_smartcard__su_as_local_user``
  already does) or a real provider fixture instead.

Per-case table
--------------

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Legacy case
     - System match
     - Cov
     - Score
     - Tier
     - Importance
     - Target file
     - Topology
     - Parametrize
     - Framework
     - Action
   * - test_preauth_indicator
     - (none)
     - gap
     - 18
     - Retire
     - low
     - —
     - —
     - —
     - —
     - retire (implementation-detail file check, not a functional user story; smart-card
       availability is already proven functionally by ``test_smartcard.py``)
   * - test_password_prompting_config_global
     - (none)
     - gap
     - 80
     - Rewrite
     - medium
     - test_authentication.py
     - AnyProvider
     - new param set: global vs per-service prompt
     - —
     - port new test
   * - test_password_prompting_config_srv
     - (none)
     - gap
     - 75
     - Backlog
     - medium
     - test_authentication.py
     - AnyProvider
     - Condense into new global-prompt test above
     - —
     - port new test (same function as global prompt)
   * - test_sc_auth_wrong_pin
     - (none)
     - gap
     - 82
     - Rewrite
     - high
     - test_smartcard.py
     - Client (local card)
     - —
     - —
     - port new test
   * - test_sc_auth
     - test_smartcard__su_as_local_user
     - duplicate
     - 30
     - Remove only
     - medium
     - —
     - —
     - —
     - —
     - remove now (same proxy-vs-local mechanism already proven)
   * - test_sc_auth_two
     - test_smartcard__two_tokens_match_on_both
     - duplicate
     - 28
     - Remove only
     - medium
     - —
     - —
     - —
     - —
     - remove now (``client.auth.su.smartcard(num_certs=2, ...)`` already exercises
       multi-cert selection regardless of token count)
   * - test_sc_auth_two_missing_name
     - (none)
     - gap
     - 68
     - Backlog
     - medium
     - test_smartcard.py
     - Client (local card)
     - extend missing-name test with num_certs=2
     - —
     - defer — port after missing-name base case
   * - test_sc_proxy_password_fallback
     - (none)
     - gap
     - 80
     - Rewrite
     - high
     - test_smartcard.py
     - Client (local card)
     - new param set: service allowed/not allowed for cert auth
     - —
     - port new test
   * - test_sc_proxy_no_password_fallback
     - (none)
     - gap
     - 80
     - Rewrite
     - high
     - test_smartcard.py
     - Client (local card)
     - Condense into pam_p11_allowed_services test above
     - —
     - port new test (same function as fallback test)
   * - test_require_sc_auth
     - (none)
     - gap
     - 82
     - Rewrite
     - high
     - test_smartcard.py
     - Client (local card)
     - —
     - —
     - port new test
   * - test_require_sc_auth_no_cert
     - (none)
     - gap
     - 66
     - Backlog
     - medium
     - test_smartcard.py
     - Client (local card)
     - —
     - Reduce ``p11_child_timeout``/``p11_wait_for_card_timeout`` to ~1s each (legacy
       used 5s/5s => ~20-40s wait); confirm exact log/stdout strings still match
     - port new test
   * - test_try_sc_auth_no_map
     - (none)
     - gap
     - 68
     - Backlog
     - medium
     - test_smartcard.py
     - Client (local card)
     - Condense into try_cert_auth test below (negative branch)
     - —
     - port new test
   * - test_try_sc_auth
     - (none)
     - gap
     - 45
     - Condense
     - medium
     - test_smartcard.py
     - Client (local card)
     - Condense into one try_cert_auth test with matching + non-matching cert
     - —
     - port new test (same function as no-map case)
   * - test_try_sc_auth_root
     - (none)
     - gap
     - 85
     - Rewrite
     - critical
     - test_smartcard.py
     - Client (local card)
     - —
     - —
     - port new test
   * - test_sc_auth_missing_name
     - (none)
     - gap
     - 84
     - Rewrite
     - high
     - test_smartcard.py
     - Client (local card)
     - new param set: empty vs whitespace-only username
     - —
     - port new test
   * - test_sc_auth_missing_name_whitespace
     - (none)
     - gap
     - 40
     - Condense
     - low
     - test_smartcard.py
     - Client (local card)
     - Condensed into missing-name test above as a parametrize value
     - —
     - port new test (same function as missing-name test)
   * - test_sc_auth_name_format
     - (none)
     - gap
     - 58
     - Condense
     - medium
     - test_smartcard.py
     - Client (local card)
     - Condense into missing-name test above (add ``full_name_format`` variant)
     - —
     - port new test (same function as missing-name test)
   * - test_krb5_auth
     - test_authentication.py / test_ldap_krb5.py (general password + Kerberos login
       and negative-password coverage via ``client.sssd.common.krb5_auth``)
     - covered
     - 22
     - Remove only
     - medium
     - —
     - —
     - —
     - —
     - remove now (basic kinit success/failure already proven extensively)
   * - test_krb5_auth_domains
     - (none)
     - gap
     - 58
     - Condense
     - medium
     - test_ldap_krb5.py
     - AnyProvider
     - Condense into a multi-domain variant of an existing krb5 test
     - —
     - low-priority backlog

**Importance values:** ``critical``, ``high``, ``medium``, ``low``.

**Topology values:** ``AnyProvider`` (responder/module-generic options); ``Client`` (no
identity provider — local user + local smart card, matching
``test_smartcard__su_as_local_user``'s existing pattern) for the certificate-auth-mode
cases, since none of ``pam_cert_auth``, ``pam_p11_allowed_services``,
``try_cert_auth``/``require_cert_auth``/``allow_missing_name`` are tied to an identity
backend.

**Parametrize values:** ``—``, ``new param set: ...``, or ``Condense into <test> ...``.

**Framework values:** ``—`` or short gap description.

Remove now
----------

* test_preauth_indicator — Retire; implementation-detail file check with no functional
  proof, and smart-card availability is already exercised functionally by
  ``test_smartcard.py``.
* test_sc_auth — duplicate of ``test_smartcard__su_as_local_user``.
* test_sc_auth_two — duplicate; ``client.auth.su.smartcard(num_certs=2, cert_selection=N)``
  already exercises multi-certificate selection regardless of how many physical tokens
  the certs are split across (see ``test_smartcard__two_tokens_match_on_both``).
* test_krb5_auth — covered; basic Kerberos login success/negative-password coverage
  already exists via ``client.sssd.common.krb5_auth(kdc)`` in ``test_authentication.py``
  and ``test_ldap_krb5.py``.

Partial coverage notes
----------------------

* No ``partial`` cases — every non-duplicate/non-retire case is a full ``gap`` (this
  behavior area, PAM certificate-auth *modes* and custom password prompts, has zero
  existing system-test coverage; only the underlying smart-card mechanics and Kerberos
  login are covered).

Framework gaps
--------------

None blocking. The three apparent risks all resolve to **existing, proven patterns**:

* Custom ``/etc/pam.d/<service>`` stacks with extra ``pam_sss.so`` options
  (``try_cert_auth`` / ``require_cert_auth`` / ``allow_missing_name``) — already done via
  ``client.fs.write("/etc/pam.d/...", ...)`` in
  ``test_authentication__user_login_with_modified_PAM_stack_provider_is_offline``.
  Back up with ``authselect apply-changes --backup=...`` first, same as that test.
  Enable smart-card support first via ``client.authselect.select("sssd", ["with-smartcard"])``,
  then overlay the extra ``pam_sss.so`` module option on the resulting service file.
* Multi-certificate selection prompts — already supported by
  ``client.auth.su.smartcard(num_certs=..., cert_selection=...)``.
* Local (non-IPA) smart-card setup — already supported by
  ``client.smartcard.setup_local_card()`` / ``initialize_card(reset=False)`` for a second
  token.

Recommended next work
----------------------

* critical — Rewrite: root must never authenticate via smart card, even with
  ``try_cert_auth`` -> ``test_smartcard.py`` (``test_try_sc_auth_root``)
* high — Rewrite: wrong PIN is rejected -> ``test_smartcard.py``
* high — Rewrite: ``pam_p11_allowed_services`` controls password-vs-PIN fallback (2 legacy
  cases, 1 parametrized test) -> ``test_smartcard.py``
* high — Rewrite: ``require_cert_auth`` succeeds with a card present -> ``test_smartcard.py``
* high — Rewrite: ``allow_missing_name`` resolves the certificate owner without a supplied
  username (3 legacy cases condensed into 1 parametrized test) -> ``test_smartcard.py``
* medium — Rewrite: custom global/per-service password prompt text (2 legacy cases, 1
  parametrized test) -> ``test_authentication.py``
* medium — Backlog: ``require_cert_auth`` times out and fails without a card (tune
  timeouts down from the legacy ~20-40s) -> ``test_smartcard.py``
* medium — Backlog: ``try_cert_auth`` succeeds on cert match, falls through on no match (2
  legacy cases condensed into 1 test) -> ``test_smartcard.py``
* medium — Backlog: missing-name resolution combined with multi-certificate selection ->
  ``test_smartcard.py``
* medium — Condense: multi-domain ``sssd.conf`` with decoy realms does not break PAM
  Kerberos auth -> ``test_ldap_krb5.py``
* Remove now: test_preauth_indicator, test_sc_auth, test_sc_auth_two, test_krb5_auth (see
  above)

Ports by importance
--------------------

critical
~~~~~~~~

* test_try_sc_auth_root — Rewrite -> test_smartcard.py

high
~~~~

* test_sc_auth_wrong_pin — Rewrite -> test_smartcard.py
* test_sc_proxy_password_fallback / test_sc_proxy_no_password_fallback — Rewrite (1
  parametrized test) -> test_smartcard.py
* test_require_sc_auth — Rewrite -> test_smartcard.py
* test_sc_auth_missing_name — Rewrite -> test_smartcard.py

medium
~~~~~~

* test_password_prompting_config_global / test_password_prompting_config_srv — Rewrite (1
  parametrized test) -> test_authentication.py
* test_require_sc_auth_no_cert — Backlog -> test_smartcard.py
* test_try_sc_auth_no_map / test_try_sc_auth — Backlog (1 test) -> test_smartcard.py
* test_sc_auth_two_missing_name — Backlog (extends missing-name test) -> test_smartcard.py
* test_sc_auth_name_format — Condense (extends missing-name test) -> test_smartcard.py
* test_krb5_auth_domains — Condense -> test_ldap_krb5.py

low
~~~

* test_sc_auth_missing_name_whitespace — Condense (extends missing-name test) ->
  test_smartcard.py
