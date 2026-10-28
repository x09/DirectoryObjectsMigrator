# Changelog

## [1.2.0] - 2026-10-27

### Fixed
- Fully retrieve large-group member ranges during analysis and verification.
  Validate range continuity and object identity/version; abort incomplete reads.
  Preserve outer LDAP page cookies during range reads and avoid the ldap3
  empty-attribute synthesis crash on explicit range requests.
- On password rejection, retry up to three times with newly generated complex
  random passwords, including fixed-password mode. Use unicodePwd only; remove
  the userPassword fallback. Persist per-account outcomes in logs and reports.
- Honor the configured random password length and the readable destination
  minPwdLength. Guarantee character categories and avoid account/name tokens.
- Mark exhausted password setup as a run error and retain the tracked object for
  a GUID-checked retry. Do not reset successfully configured passwords on reruns.
- Show destination-policy requirements and supplied Samba defaults in the password
  options tab, including a visible explanation of fixed-to-random fallback.
- Preserve accountExpires as its exact LDAP integer instead of passing it through
  datetime conversion. Live MS AD → Samba validation exposed a never-expire sentinel
  being written as a finite date in year 9999. Verification recognizes 0 and
  9223372036854775807 as equivalent without hiding changes to finite timestamps.
- Verify individual GUID mappings, transformed attribute values and direct group
  membership/reference values, rather than relying on equal object counts.
  Include deferred-reference parents touched outside the selected subtree.
- Persist detailed verification findings in SQLite and HTML/TXT reports. Missing
  mappings, lost values, unexpected references and incomplete ranged reads fail
  verification; tracked unresolved references remain explicit warnings.
- Honor the organizational_unit configuration for OU handlers and migrate OU
  managedBy references, which previously could be omitted.
- Read unlimited subtree searches in 500-entry LDAP pages, including analysis and
  verification. Abort on failed pages instead of using partial directory results.
- Check destination parents and domain-wide sAMAccountName/transformed UPN
  conflicts in preview and immediately before creation. Account for OUs scheduled
  earlier in the run and duplicate identities in the plan, including Dry Run.
- Preserve escaped commas when extracting a destination parent DN.
- Scope tracked mappings and deferred references to the source/destination domain
  GUID pair. Upgrade older SQLite databases with a backup; retain ambiguous legacy
  history without automatically applying it.
- Validate tracked destination GUIDs before reuse, follow renamed/moved objects,
  and block missing or replaced objects. Validate deferred-reference parents too.
- Remove automatic reference matching by sAMAccountName, including after database
  reset. Unverified references remain deferred instead of granting membership to
  a same-named account. Preview shows verification failure reasons.
- Acknowledge deferred references only after a successful LDAP update or a read
  confirming the value already exists. Rejected writes remain pending for retry;
  duplicate tracking rows do not produce duplicate LDAP values.
- Preserve failed initial reference writes for retry and include reference errors
  in the run statistics. Dry Run leaves pending rows unchanged.
- Distinguish clean completion, completion with warnings/errors, cancellation and
  fatal failure in the engine, database, GUI and HTML/TXT reports. Verification
  failures and missing objects no longer result in a green success message.
- Retain the run ID and partial results after fatal failures so a report remains
  available. Empty scopes now finalize their database run.

### Validation
- Identity regressions cover domain separation, replaced/rebuilt objects and
  domains, renames, legacy schema upgrades, GUID formats and same-login accounts.
- Failure-injection regressions cover rejected writes, lost LDAP replies, retries,
  dry runs, verification failures, cancellation and GUI/report status.


## [Unreleased]

### Added in the v1.1 working copy (2026-10-16)
- Visible loading feedback in the branch picker: animated indeterminate progress
  bar and a loading label on each pending branch. The bar remains visible until
  all requests finish, including while closing an active connection.
- Single-branch Base DN picker beside the main window's text field. Shows source
  domain, OUs and containers, with lazy loading, paged LDAP reads, in-dialog cache,
  refresh and retryable errors. Browsing uses a separate background connection and
  needs no destination connection. Manual DN entry remains available.
- Changing Base DN invalidates the previous migration plan. Changing connection
  settings also clears cached credentials/connections and invalidates the plan.
- Branch browser regression suite covering paging consumption, Unicode/escaped
  DNs, lazy loading/cache, cancellation, connection errors and main-window integration.



### Fixed
- **AD branch browser referrals**: Domain-root results may contain continuation
  references to other naming contexts (such as DNS application partitions).
  The picker now skips these reference records and retains local OU/container
  entries instead of aborting the branch. Referral following is disabled for this
  read and restored afterwards; actual LDAP errors still fail visibly.
- **Base DN validation**: Analyzer now checks that the Base DN exists in the source domain before starting analysis. Previously, entering a non-existent DN produced a cryptic LDAP error; now a clear message is shown: "Base DN does not exist in the source domain: ..."

- **Deferred references after database reset**: When the migration database is reset but objects already exist in the destination domain, reference resolution now checks the destination domain by `sAMAccountName` if the object is not in `migration_map`. This prevents false "deferred" references to objects that were migrated before the reset. The check is performed in both:
  - **Migration planning** (`build_plan`): so the preview shows accurate deferred counts
  - **Migration execution** (`resolve_reference`): so references are actually resolved during migration

- **Preview dialog deferred references tab**: Now shows only references that will remain truly deferred after the migration run. References that can be resolved immediately (because the target already exists in the destination) are no longer shown in this tab, reducing confusion. The summary notes still indicate how many deferred references will be resolved in this run.

- **Migration button styling**: The "Start Migration" button now displays with grey styling when disabled (before analysis is run), making it visually clear that the button cannot be clicked yet. Previously it always appeared green.

- **Builtin domain groups filtering**: Well-known groups from the Builtin domain (S-1-5-32-*) such as Administrators, Users, Guests, and others are now properly recognized and excluded from migration by their full SID. Previously only domain-relative RIDs were checked, allowing Builtin groups to pass through. The check now covers:
  - Well-known absolute SIDs (S-1-5-32-544 through S-1-5-32-580)
  - Domain-relative RIDs (500, 502, 512-527, etc.)
  - Name-based fallback when objectSid is unavailable

### Added
- **Clear Log button**: A "Clear Log" button has been added above the log viewer, allowing operators to clear the log window without restarting the application.

---

## [1.0.0] - 2026-09-18

Initial release with core migration functionality:
- User, group, and OU migration between AD/Samba domains
- Deferred reference resolution across multiple runs
- Conflict detection and safe handling (never overwrites existing objects)
- Bilingual interface (Russian/English)
- Comprehensive test coverage (11 test suites)
- Built-in object filtering (Administrator, Domain Admins, krbtgt, etc.)
- Migration database reset with automatic backup
