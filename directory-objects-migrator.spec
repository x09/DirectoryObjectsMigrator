%define _unpackaged_files_terminate_build 1

Name: DirectoryObjectsMigrator
Version: 2.0
Release: alt1
Summary: Migrate directory service objects from AD or FreeIPA to Samba AD
License: %gpl3only
Group: System/Configuration/Other
Url: https://github.com/x09/DirectoryObjectsMigrator
BuildArch: noarch

BuildRequires(pre): rpm-build-python3
BuildRequires: gettext-tools
BuildRequires: rpm-build-licenses

Requires: python3-module-ldap3
Requires: python3-module-PyQt5
Requires: python3-modules-sqlite3
Requires: python3-module-yaml

Source0: %name-v%version.tar.gz

%add_python3_path %_datadir/%name

%description -l ru_RU.UTF-8
Мигратор объектов службы каталога (AD/FreeIPA) в Samba AD.
Переносит OU, пользователей, группы и контакты из AD, пользователей и группы
из FreeIPA. Поддерживает предпросмотр, историю, проверку результата и RFC2307.

%description
Migrate directory service objects from Microsoft AD, Samba AD or FreeIPA to
Samba AD. Supports AD OUs, users, groups and contacts, FreeIPA users and groups,
preview, migration history, verification and optional RFC2307 attributes.

%prep
%setup -q -n %name-v%version

%build
for language in ru en; do
    msgfmt locale/$language/LC_MESSAGES/DirectoryObjectMigrator.po \
        -o locale/$language/LC_MESSAGES/DirectoryObjectMigrator.mo
done

%install
for language in ru en; do
    install -D -m644 locale/$language/LC_MESSAGES/DirectoryObjectMigrator.mo \
        %buildroot%_datadir/locale/$language/LC_MESSAGES/DirectoryObjectMigrator.mo
done

# Install runtime sources and data only, including the FreeIPA source package.
find gui core utils database config -type f \
    \( -name '*.py' -o -name '*.yaml' -o -name '*.sql' \) | while read -r file; do
    install -D -m644 "$file" "%buildroot%_datadir/%name/$file"
done
find resources -type f \( -name '*.svg' -o -name '*.png' \) | while read -r file; do
    install -D -m644 "$file" "%buildroot%_datadir/%name/$file"
done
install -D -m644 resources/icon.svg %buildroot%_iconsdir/%name.svg
install -D -m644 %name.desktop %buildroot%_desktopdir/%name.desktop
install -D -m755 main.py %buildroot%_bindir/%name

%files
%doc README.md CHANGELOG.md LICENSE docs/USER_GUIDE.md docs/ARCHITECTURE.md
%_bindir/%name
%_desktopdir/%name.desktop
%_datadir/%name/
%_datadir/locale/ru/LC_MESSAGES/DirectoryObjectMigrator.mo
%_datadir/locale/en/LC_MESSAGES/DirectoryObjectMigrator.mo
%_iconsdir/%name.svg

%changelog
* Thu Nov 26 2026 Anton Shevtsov <shevtsov.anton@gmail.com> 2.0-alt1
- Add FreeIPA migration, RFC2307 and confirmed recreation of deleted tracked objects.
- Add configurable FreeIPA attribute mappings and optional shortening of long logins.
- Improve migration preview, conflict guidance, row selection and CSV export.
- Update translations, documentation and application metadata.

* Thu Oct 29 2026 Anton Shevtsov <shevtsov.anton@gmail.com> 1.3-alt1
- Exclude DNS service groups and report unsupported references as skipped.
- Preserve skipped-reference history without treating it as resolved.
- Include ordinary CN=Users objects in domain-root migrations.
- Run analysis and migration planning in the background with a busy indicator.
- Fix migration progress translations and preview completion messages.

* Wed Oct 28 2026 Anton Shevtsov <shevtsov.anton@gmail.com> 1.2-alt1.git917c9bc
- Add paged LDAP searches and complete large-group member retrieval.
- Validate destination parents, object identities and naming conflicts.
- Isolate migration tracking by domain pair with automatic database upgrade.
- Improve deferred reference handling and retry safety.
- Verify migrated objects, attribute values and group membership.
- Improve password generation and retry rejected passwords.
- Fix accountExpires and OU managedBy migration.
- Improve migration statuses, reports, translations and documentation.

* Fri Oct 16 2026 Anton Shevtsov <shevtsov.anton@gmail.com> 1.1-alt1.git7ecce2c
- Added tree-based migration scope selection

* Mon Sep 21 2026 Anton Shevtsov <shevtsov.anton@gmail.com> 1.0-alt1.gitfde31cc
- Initial release
