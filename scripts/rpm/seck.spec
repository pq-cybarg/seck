Name:    seck
Version: 0.1.0
Release: 1%{?dist}
Summary: Sandboxed-LLM file/project analyzer
License: AGPLv3+
URL:     https://github.com/seck-project/seck

%description
seck runs a local LLM against a file or directory inside a
Landlock+seccomp sandbox with strong typestate guarantees that
untrusted bytes never reach argv/env/paths/URLs/DNS.

%files
/usr/bin/seck

%changelog
* Thu May 22 2026 pq-cybarg <resistant@tuta.com> 0.1.0-1
- Initial RPM packaging.
