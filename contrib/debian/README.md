
Debian
====================
This directory contains files used to package esportscoind/esportscoin-qt
for Debian-based Linux systems. If you compile esportscoind/esportscoin-qt yourself, there are some useful files here.

## esportscoin: URI support ##


esportscoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install esportscoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your esportscoinqt binary to `/usr/bin`
and the `../../share/pixmaps/esportscoin128.png` to `/usr/share/pixmaps`

esportscoin-qt.protocol (KDE)

