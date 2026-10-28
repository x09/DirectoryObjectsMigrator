%define _unpackaged_files_terminate_build 1

Name: DirectoryObjectsMigrator
Version: 1.2
Release: alt1.git917c9bc
Summary: A tool for migrating Active Directory objects from Microsoft AD to Samba AD
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

Source0: %name-v%version.tgz

%add_python3_path %_datadir/%name

%description -l ru_RU.UTF-8
Directory Objects Migrator — инструмент для миграции объектов Active Directory
из Microsoft AD в Samba AD

%description
Directory Objects Migrator is a utility designed to migrate Active Directory
objects from a Microsoft Active Directory domain to a Samba Active Directory
domain

%prep
%setup -q -n %name-v%version 

%install
for language in ru en; do
	mkdir -p %buildroot/%_datadir/locale/$language/LC_MESSAGES/
	install -m644 locale/$language/LC_MESSAGES/DirectoryObjectMigrator.mo %buildroot/%_datadir/locale/$language/LC_MESSAGES/
done

mkdir -p %buildroot/%_datadir/%name/{gui,core,utils,database,resources,config}
mkdir  %buildroot/%_datadir/%name/core/object_handlers/

cp -r gui/* %buildroot/%_datadir/%name/gui/
cp -r core/* %buildroot/%_datadir/%name/core/
cp -r utils/* %buildroot/%_datadir/%name/utils/
cp -r database/* %buildroot/%_datadir/%name/database/
cp -r resources/* %buildroot/%_datadir/%name/resources/
cp -r config/* %buildroot/%_datadir/%name/config/

mkdir -p %buildroot/%_iconsdir
cp resources/icon.svg %buildroot/%_iconsdir/%name.svg

mkdir -p  %buildroot/%_desktopdir
cp %name.desktop %buildroot/%_desktopdir/%name.desktop


mkdir -p %buildroot/%_bindir/
cp main.py %buildroot/%_bindir/%name
chmod 755 %buildroot/%_bindir/%name


#%check
#%__python3 -m pytest -vra tests/

%files
%doc README.md 
%_bindir/%name
%_desktopdir/%name.desktop
%_datadir/%name/*
%_datadir/locale/*
%_iconsdir/%name.svg


%changelog
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
