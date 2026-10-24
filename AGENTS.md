Comprehensive tests for sdwdate-gui -- an offscreen unit suite, a wire-protocol
and state fuzzer, and an X11/Wayland/SNI integration suite -- are too
high-volume for human review and live in the AI-maintained dist-ai repo, not
here:

  https://github.com/org-ai-assisted/dist-ai -> usr/share/sdwdate-gui-tests/

Run them against this checkout:

    PYTHONPATH="$PWD/usr/lib/python3/dist-packages" sdwdate-gui-tests              # offscreen unit
    PYTHONPATH="$PWD/usr/lib/python3/dist-packages" sdwdate-gui-tests-integration  # X11/Wayland/SNI

## By design -- do not re-report or "fix"

Intentional behavior; not bugs. Do not file reports for these or patch them to
accept the input.

- Control characters (TAB, CR, other C0, DEL) in a status message: the server
  rejects the frame and kicks the client. sdwdate status messages never carry
  control bytes, CRs can be malicious, and kicking unexpected bytes is the
  intended defense. Do not make the client escape or strip them to pass. (#10)
- A client name / hostname containing a space or control character: the server
  kicks the client. Exotic hostnames are reasonably treated as malicious. Do
  not escape or sanitize the name to accept it. (#14)
- A kicked client's state is undefined. Kicking may leave stale fields (e.g. a
  failed octal escape in set_sdwdate_status keeps the old message). The client
  is scheduled for deletion via drop_client, so its residual state is never an
  observable the server acts on. Kick-anytime without pre-cleanup is intended;
  do not add cleanup-before-kick or treat the stale state as a bug. (#18)
- The Qubes qrexec connection header is stamped by dom0 (`<service> <source-vm>`),
  NOT by the untrusted client, so __parse_qubes_data trusts it: it takes
  qrexec_header_parts[1] as the source-VM name and does not reject a header with
  extra tokens (dom0 never emits one). Do not add untrusted-header field
  validation here; the trust boundary is dom0/qrexec, not the header text.

## Tray icon: QSystemTrayIcon backend binds at construction

- `QSystemTrayIcon` binds its backend (legacy XEmbed vs StatusNotifier/SNI
  D-Bus) at CONSTRUCTION, irreversibly. Constructed before the panel's
  `org.kde.StatusNotifierWatcher` is on the session bus, Qt falls back to
  XEmbed; an SNI-only panel (lxqt-panel, waybar) then NEVER shows the icon
  (startup race, e.g. a Whonix sysmaint-split session). Neither an
  `isSystemTrayAvailable()` poll before `show()` nor `hide()`+`show()` recovers
  it; only DEFERRING construction until `isSystemTrayAvailable()` is true picks
  SNI (Qt5 == Qt6).
- Latent, not yet guarded: `main()` constructs `SdwdateTrayIcon()`
  unconditionally
  (`usr/lib/python3/dist-packages/sdwdate_gui/sdwdate_gui_server.py`). Deferring
  the construct is a behaviour change (what to do when no tray host ever appears)
  -- a maintainer call, not a silent fix.
- Reproduce headless with `xfce4-panel` 4.20 libsystray under Xvfb (a real SNI
  host); stalonetray (XEmbed auto-re-embed) and trayer/waybar (no headless
  watcher) cannot reveal it. dist-ai `sdwdate-gui-tests-integration`
  (`tray_startup_race_reproducer.py`) pins the Qt construction-order behaviour.
