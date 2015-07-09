%global composer_vendor  fkooman
%global composer_project rest-plugin-indieauth

%global github_owner     fkooman
%global github_name      php-lib-rest-plugin-indieauth

Name:       php-%{composer_vendor}-%{composer_project}
Version:    0.5.2
Release:    1%{?dist}
Summary:    IndieAuth Authentication plugin for fkooman/rest

Group:      System Environment/Libraries
License:    ASL 2.0
URL:        https://github.com/%{github_owner}/%{github_name}
Source0:    https://github.com/%{github_owner}/%{github_name}/archive/%{version}.tar.gz
BuildArch:  noarch

Provides:   php-composer(%{composer_vendor}/%{composer_project}) = %{version}

Requires:   php(language) >= 5.4
Requires:   php-dom
Requires:   php-filter
Requires:   php-libxml
Requires:   php-openssl
Requires:   php-pcre
Requires:   php-spl
Requires:   php-standard

Requires:   php-composer(fkooman/rest) >= 0.9.0
Requires:   php-composer(fkooman/rest) < 0.10.0
Requires:   php-composer(guzzlehttp/guzzle) >= 5.3
Requires:   php-composer(guzzlehttp/guzzle) < 6.0

%description
Library written in PHP to make it easy to develop REST applications.

%prep
%setup -qn %{github_name}-%{version}

%build

%install
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/php
cp -pr src/* ${RPM_BUILD_ROOT}%{_datadir}/php

%files
%defattr(-,root,root,-)
%dir %{_datadir}/php/%{composer_vendor}/Rest/Plugin/IndieAuth
%{_datadir}/php/%{composer_vendor}/Rest/Plugin/IndieAuth/*
%doc README.md CHANGES.md composer.json
%license COPYING

%changelog
* Thu Jul 09 2015 François Kooman <fkooman@tuxed.net> - 0.5.2-1
- update to 0.5.2

* Thu Jul 09 2015 François Kooman <fkooman@tuxed.net> - 0.5.1-1
- update to 0.5.1

* Sun Jun 28 2015 François Kooman <fkooman@tuxed.net> - 0.5.0-1
- update to 0.5.0

* Tue May 05 2015 François Kooman <fkooman@tuxed.net> - 0.4.0-1
- update to 0.4.0

* Fri May 01 2015 François Kooman <fkooman@tuxed.net> - 0.3.0-1
- update to 0.3.0

* Sun Apr 12 2015 François Kooman <fkooman@tuxed.net> - 0.2.2-1
- update to 0.2.2

* Tue Mar 24 2015 François Kooman <fkooman@tuxed.net> - 0.2.1-1
- update to 0.2.1

* Tue Mar 24 2015 François Kooman <fkooman@tuxed.net> - 0.2.0-1
- update to 0.2.0

* Sun Mar 15 2015 François Kooman <fkooman@tuxed.net> - 0.1.3-1
- update to 0.1.3

* Sun Mar 15 2015 François Kooman <fkooman@tuxed.net> - 0.1.2-1
- update to 0.1.2

* Tue Mar 10 2015 François Kooman <fkooman@tuxed.net> - 0.1.1-1
- update to 0.1.1

* Tue Mar 10 2015 François Kooman <fkooman@tuxed.net> - 0.1.0-1
- initial package
