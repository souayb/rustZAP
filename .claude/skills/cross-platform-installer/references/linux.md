# Linux packaging detail

## `.deb` (Debian/Ubuntu)

Control metadata that must be correct: `Package`, `Version`, `Architecture` (`amd64`/`arm64`), `Depends`, `Maintainer`, `Description`, `Section`, `Priority`.

Layout inside the package follows FHS: binaries in `/usr/bin`, GUI app payload in `/opt/<app>`, config in `/etc/<app>`, desktop entry in `/usr/share/applications`, icons in `/usr/share/icons/hicolor/<size>/apps`, systemd unit in `/lib/systemd/system`.

Maintainer scripts (keep idempotent, exit non-zero on real failure):
- `preinst` — pre-install (rare).
- `postinst` — create users/dirs, `systemctl daemon-reload` + `enable` if a service, update icon/desktop caches.
- `prerm` — stop/disable service before removal.
- `postrm` — clean up on `purge`; **do not delete user data** on plain `remove`.

Hand-built structure (when not using cargo-deb):

```
pkgroot/
├── DEBIAN/{control,postinst,prerm,postrm}
├── usr/bin/<app>
├── usr/share/applications/<app>.desktop
└── lib/systemd/system/<app>.service   # if a service
dpkg-deb --root-owner-group --build pkgroot <app>_<version>_<arch>.deb
lintian <app>_<version>_<arch>.deb     # verify
```

## `.rpm` (Fedora/RHEL/openSUSE)

Spec fields: `Name`, `Version`, `Release`, `BuildArch` (`x86_64`/`aarch64`), `Requires`, `%files`, `%post`/`%preun`/`%postun` scriptlets mirroring the deb ones. Build with `rpmbuild -bb app.spec` or `cargo generate-rpm` for Rust.

Verify: `rpm -qip *.rpm` (metadata), `rpm -qlp *.rpm` (files), `rpmlint *.rpm`.

## AppImage (portable)

Self-contained; must run on a clean, older-glibc supported distro. Bundle needed libs, but not the world.

```
AppDir/
├── AppRun                       # entrypoint, execs usr/bin/<app>
├── <app>.desktop                # Categories, Icon; Terminal=true for CLI
├── <app>.png
└── usr/{bin,lib,share}/
linuxdeploy --appdir AppDir --output appimage   # or appimagetool AppDir
```

Test on a distro *older* than the build host to catch glibc issues. Prefer musl static builds for Rust/Go CLIs to sidestep glibc entirely.

## Flatpak / Snap

Only add on an explicit distribution requirement (sandboxing, store presence). Both need a manifest and their own toolchains (`flatpak-builder`, `snapcraft`); don't introduce them by default.

## Signing / integrity

Debian/RPM repos sign package indexes (GPG). For direct-download releases, at minimum publish `SHA256SUMS` and optionally a detached GPG signature (`gpg --armor --detach-sign SHA256SUMS`). Protect the signing key; never commit it.
