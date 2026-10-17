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
