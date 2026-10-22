#!/usr/bin/env python3
"""BIOS Recovery Suite - Professional BIOS repair and management tool."""

import os
import sys


def _run_mea_child():
    """Run ME Analyzer in child mode without initializing Qt."""
    try:
        from bios_recovery.third_party.mea import MEA_PATH
    except Exception as e:
        print(f"ME Analyzer integration not found: {e}", file=sys.stderr)
        sys.exit(1)

    # In frozen (windowed) apps stdout is None; MEA prints unconditionally.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")

    # MEA's get_script_dir() checks sys.frozen and uses the exe dir, but the
    # .dat files are bundled in the package data dir. Clear the flag so MEA
    # resolves its script dir from __file__ (MEA_PATH) instead.
    if getattr(sys, "frozen", False):
        try:
            del sys.frozen
        except Exception:
            pass

    new_argv = [MEA_PATH]
    for a in sys.argv[1:]:
        if a == "--mea-child":
            continue
        new_argv.append(a)
    sys.argv = new_argv

    try:
        with open(MEA_PATH, encoding="utf-8", errors="replace") as f:
            code = compile(f.read(), MEA_PATH, "exec")
        exec(code, {"__name__": "__main__", "__file__": MEA_PATH})
    except SystemExit:
        raise
    except Exception:
        import traceback

        traceback.print_exc()
        sys.exit(1)


def _is_mea_child():
    return any(a == "--mea-child" for a in sys.argv[1:])


def _ensure_streams():
    """A windowed Windows build has no stdout or stderr, and print() would drop output.

    On Windows, attach to the console that started the program when there is one, so
    CLI output reaches the user. Otherwise send the output to nowhere, without errors.
    """
    if sys.stdout is not None and sys.stderr is not None:
        return
    if sys.platform == "win32":
        try:
            import ctypes

            if ctypes.windll.kernel32.AttachConsole(-1):
                if sys.stdout is None:
                    sys.stdout = open("CONOUT$", "w", encoding="utf-8")
                if sys.stderr is None:
                    sys.stderr = open("CONOUT$", "w", encoding="utf-8")
                return
        except (AttributeError, OSError):
            pass
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")


if _is_mea_child():
    _run_mea_child()
    sys.exit(0)


def _app_dir():
    """Directory the running exe lives in (the folder Qt loads DLLs from)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return None


def _diagnose_qt_import_failure(exc):
    """Explain a Qt DLL load failure instead of dumping a raw traceback.

    The overwhelmingly common cause is a stale DLL sitting next to the exe:
    Windows resolves DLLs from the app folder BEFORE the system folder, so one
    leftover icu*.dll / Qt6*.dll from an older build shadows the correct one.
    """
    lines = [
        "",
        "=" * 72,
        "BIOS Recovery Suite could not start: Qt failed to load.",
        "",
        f"Error: {exc}",
        "",
    ]

    app_dir = _app_dir()
    if app_dir:
        suspects = []
        try:
            for name in sorted(os.listdir(app_dir)):
                low = name.lower()
                if low.endswith(".dll") and (low.startswith("icu") or low.startswith("qt6")):
                    suspects.append(name)
        except OSError:
            pass
        if suspects:
            lines += [
                "LIKELY CAUSE - stale DLLs in the program folder:",
                *[f"    {s}" for s in suspects],
                "",
                "Windows loads DLLs from the app folder before the system folder,",
                "so these shadow the correct system copies. Fix:",
                "",
                "  1. Uninstall 'BIOS Recovery Suite' (Control Panel > Programs).",
                "  2. DELETE the leftover folder:",
                f"     {app_dir}",
                "  3. Download a fresh installer and install into a clean folder.",
            ]
        else:
            lines += [
                "No obviously stale DLLs were found in the program folder.",
                "Next most likely cause: this Windows build is too old for the",
                "Qt version this app needs (Qt 6 requires Windows 10 1809 or",
                "newer). Run 'winver' to check.",
            ]
    else:
        lines.append("Running from source, not a packaged build.")

    lines += [
        "",
        "If the folder was already clean, install the Microsoft Visual C++",
        "redistributable (x64) from https://aka.ms/vs/17/release/vc_redist.x64.exe",
        "=" * 72,
        "",
    ]
    return "\n".join(lines)


def _library_cli(argv) -> int:
    """`library add-folder|remove-folder|list|scan [PATH]`.

    Manages the user-chosen tool and firmware folders.
    """
    from bios_recovery.core import user_library as lib

    usage = (
        "usage: library add-folder PATH | remove-folder PATH | list | scan | identify FILE\n"
        "The app ships no Intel tools or ME firmware; add the folders where you keep yours.\n"
        "scan lists files without running them; identify runs one file (-h) and caches the result."
    )
    if not argv:
        print(usage, file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd in ("add-folder", "remove-folder"):
        if len(rest) != 1:
            print(usage, file=sys.stderr)
            return 2
        try:
            current = lib.add_folder(rest[0]) if cmd == "add-folder" else lib.remove_folder(rest[0])
        except (ValueError, OSError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print(f"config: {lib.config_path()}")
        for f in sorted(set(current.tools_folders) | set(current.firmware_folders)):
            print(f"  folder: {f}")
        return 0
    if cmd == "list":
        try:
            current = lib.load_library()
        except OSError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print(f"config: {lib.config_path()}")
        print(f"  tools folders:    {current.tools_folders or '(none)'}")
        print(f"  firmware folders: {current.firmware_folders or '(none)'}")
        return 0
    if cmd == "identify":
        if len(rest) != 1:
            print(usage, file=sys.stderr)
            return 2
        print(f"running {rest[0]} once with -h as this user to read its identity", file=sys.stderr)
        try:
            probe = lib.identify_tool(rest[0])
        except (ValueError, OSError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        if not probe.identified:
            print(f"not identified: {probe.error}")
            return 4
        print(f"identified: {probe.family} {probe.version} {probe.platform}".rstrip())
        return 0
    if cmd == "scan":
        try:
            result = lib.scan()
        except OSError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        if not result.folders:
            print("no folders added; use: library add-folder PATH")
            return 0
        print(f"tools found: {len(result.tools)} (listed, not run)")
        for t in result.tools:
            label = f"{t.family} {t.version}" if t.identified else "unidentified"
            print(f"  {label:<24} {t.platform:<8} {t.release:<18} {t.path}")
        if any(not t.identified for t in result.tools):
            print("  run 'library identify FILE' to identify a tool (this runs it once)")
        print(f"firmware found: {len(result.firmware)}")
        for fw in result.firmware:
            print(f"  ME {fw.me_version:<16} {fw.size:>10,} bytes  {fw.path}")
        for note in result.skipped:
            print(f"  note: {note}")
        return 0
    print(usage, file=sys.stderr)
    return 2


def _verify_rebuild_cli(argv) -> int:
    """`verify-rebuild ORIGINAL CANDIDATE`: read-only region gate for a rebuilt image."""
    from bios_recovery.core.rebuild_verify import describe, verify_rebuild

    if len(argv) != 2:
        print("usage: verify-rebuild ORIGINAL CANDIDATE", file=sys.stderr)
        return 2
    for path in argv:
        if not os.path.isfile(path):
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2
    result = verify_rebuild(argv[0], argv[1])
    for line in describe(result):
        print(line)
    return 0 if result.accepted else 3


def _int_arg(text: str) -> int:
    import argparse

    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text}") from None


def _cli_main(argv) -> int:
    """Offline CLI mode: `bios-recovery <command> FILE [options]`.

    Mirrors the paid suites' "all CMD line supported" behavior using the app's
    own engines. Never touches Qt.
    """
    import argparse

    p = argparse.ArgumentParser(prog="bios-recovery", description="BIOS Recovery Suite (CLI mode)")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, help_):
        s_ = sub.add_parser(name, help=help_)
        s_.add_argument("file", help="input file")
        s_.add_argument("-o", "--out", default=None, help="output path / dir")
        s_.add_argument(
            "--force",
            action="store_true",
            help="run even when the tool does not apply to this image",
        )
        return s_

    add("analyze", "analyze a BIOS image")
    add("extract", "extract firmware components (ANY brand EXE/capsule)")
    s_gr = add("graft", "repair a damaged dump by grafting from a donor")
    s_gr.add_argument("--donor", required=True, help="known-good capsule/dump")
    add("capsule", "strip an AMI capsule to its bare flash image")
    s_me = add("me-clean", "clean/soft-disable the Intel ME region")
    s_me.add_argument("--no-hap", action="store_true", help="skip HAP soft-disable")
    s_me.add_argument(
        "--keep-modules", action="store_true", help="do not remove non-essential partitions"
    )
    s_me.add_argument(
        "--truncate", action="store_true", help="cut the empty tail after the last kept partition"
    )
    s_me.add_argument(
        "--lock", action="store_true", help="set the descriptor lock (removes ME write access)"
    )
    add("remove-passwords", "strip password/security structures")
    add("recover-passwords", "recover DVAR-stored Dell BIOS passwords from a dump")
    add("dmi", "show DMI/SMBIOS identity")
    s_sd = add("set-dmi", "write identity (serial/uuid/mac, fixed-size edits)")
    s_sd.add_argument("--serial", default=None)
    s_sd.add_argument("--uuid", default=None)
    s_sd.add_argument("--mac", default=None)
    s_ec = add("ec-extract", "locate + extract the EC firmware region")
    s_ec.add_argument(
        "--offset", type=_int_arg, default=None, help="region offset (with --size, skips detection)"
    )
    s_ec.add_argument(
        "--size", type=_int_arg, default=None, help="region size in bytes (alone: end-anchored)"
    )
    s_ec.add_argument("--overwrite", action="store_true", help="replace the output if it exists")
    add("ec-scan", "advisory scan: which EC patches' signatures are present")
    s_fi = add(
        "fit-info",
        "CSME System Tools release for this image's ME; "
        "--tool identifies a FIT/MFIT binary you supplied",
    )
    s_fi.add_argument("--tool", default=None, help="path to a Flash Image Tool binary you obtained")

    args = p.parse_args(argv)
    f = args.file
    if not os.path.exists(f):
        print(f"Error: file not found: {f}", file=sys.stderr)
        return 2
    if args.command in ("ec-extract", "ec-scan") and not os.path.isfile(f):
        print(f"Error: not a file: {f}", file=sys.stderr)
        return 2

    tool = _CLI_TOOL_FOR_COMMAND.get(args.command)
    if tool and not args.force:
        from bios_recovery.core.traits import classify
        from bios_recovery.core.traits_matrix import tool_matrix

        with open(f, "rb") as fh:
            row = tool_matrix(classify(fh.read())).get(tool)
        if row is not None and not row.applies:
            print(
                f"Refused: {tool} does not apply to this image - {row.reason}. "
                f"Use --force to run it anyway.",
                file=sys.stderr,
            )
            return 3

    if args.command == "analyze":
        from bios_recovery.core.bios_analyzer import BiosAnalyzer

        r = BiosAnalyzer().analyze(f)
        print(f"type:       {r.bios_type.name}")
        print(f"size:       {r.file_size:,}")
        print(f"me_version: {r.me_version or 'n/a'}")
        print(f"me_type:    {r.me_type or 'n/a'}")
        for reg in r.regions:
            print(f"  region:   {reg.name} @{reg.offset:#x} size {reg.size:#x}")
        for i in r.issues:
            print(f"  issue:    {i}")
        for w in r.warnings:
            print(f"  warning:  {w}")
        return 0

    if args.command == "extract":
        from bios_recovery.manufacturers.common.bios_extractor import BiosExtractor

        r = BiosExtractor().extract(f, output_dir=args.out)
        print(f"method: {r.method_used} success={r.success}")
        if r.output_dir:
            print(f"dir:    {r.output_dir}")
        for msg in r.messages:
            print(f"  * {msg}")
        for x in r.files:
            print(f"  {x['type']}: {x['name']} ({x['size']:,} bytes @ {x['offset']})")
        return 0 if r.success else 1

    if args.command == "graft":
        from bios_recovery.core.bios_repair import BiosRepairEngine

        rep = BiosRepairEngine().auto_graft_from_donor(f, args.donor, args.out)
        for op in rep.operations:
            print(f"  + {op}")
        for w in rep.warnings:
            print(f"  ! {w}")
        if rep.output_path:
            print(f"out: {rep.output_path}")
        return 0 if rep.success else 1

    if args.command == "capsule":
        from bios_recovery.manufacturers.common.bios_capsule import extract_flashable_image

        info_ = extract_flashable_image(f, output_path=args.out)
        if not info_.success:
            print("\n".join(info_.messages), file=sys.stderr)
            return 1
        print(f"header: {info_.header_size:#x}")
        print(f"image:  {info_.image_size:#x}")
        print(f"sha256: {info_.image_sha256}")
        print(f"out:    {info_.output_path}")
        return 0

    if args.command == "me-clean":
        from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner

        rep_ = IntelMECleaner().clean(
            f,
            output_path=args.out,
            soft_disable=not args.no_hap,
            truncate=args.truncate,
            remove_modules=not args.keep_modules,
            descriptor_lock=args.lock,
        )
        for m in rep_.messages:
            print(f"  * {m}")
        if rep_.output_path:
            print(f"out: {rep_.output_path}")
        return 0 if rep_.status.name in ("SUCCESS", "ALREADY_CLEAN") else 1

    if args.command == "remove-passwords":
        from bios_recovery.core.password_remover import PasswordRemover

        out_f = args.out or os.path.splitext(f)[0] + "_nopass.bin"
        rep_ = PasswordRemover().remove_passwords(f, out_f)
        print(f"status: {rep_.status.name}")
        for m in rep_.messages:
            print(f"  * {m}")
        if rep_.output_path:
            print(f"out: {rep_.output_path}")
        return 0 if rep_.output_path else 1

    if args.command == "recover-passwords":
        from bios_recovery.manufacturers.dell.dvar_passwords import recover_passwords

        rep_ = recover_passwords(f)
        print(f"success: {rep_.success}")
        print(f"message: {rep_.message}")
        for pww in rep_.passwords:
            print(
                f"  @0x{pww.record_offset:x}: {pww.password!r} "
                f"(len {pww.length}, {pww.recovered_from})"
            )
        for n in rep_.notes:
            print(f"  {n}")
        return 0 if rep_.success else 1

    if args.command == "dmi":
        from bios_recovery.core.dmi_editor import DMIEditor

        info_ = DMIEditor().info(f)
        if not info_.get("found"):
            print(info_.get("message", "not found"), file=sys.stderr)
            return 1
        s_ = info_.get("serials", {})
        print(f"system serial   : {s_.get('system')}")
        print(f"baseboard serial: {s_.get('baseboard')}")
        print(f"uuid            : {info_.get('uuid')}")
        print(f"mac             : {info_.get('mac') or 'n/a'}")
        return 0

    if args.command == "set-dmi":
        from bios_recovery.core.dmi_editor import DMIEditor

        rep_ = DMIEditor().set_identity(
            f, output_path=args.out, serial=args.serial, uuid=args.uuid, mac=args.mac
        )
        for op in rep_.operations:
            print(f"  + {op}")
        for w in rep_.warnings:
            print(f"  ! {w}")
        if rep_.message:
            print(f"  # {rep_.message}")
        if rep_.output_path:
            print(f"out: {rep_.output_path}")
        return 0 if rep_.success else 1

    if args.command == "ec-extract":
        from bios_recovery.platforms.ec.ec_patcher import ECPatcher, ECStatus

        out_f = args.out or os.path.splitext(f)[0] + "_ec.bin"
        result = ECPatcher().extract_ec(
            f, out_f, offset=args.offset, size=args.size, overwrite=args.overwrite
        )
        print(result.message)
        if result.status != ECStatus.SUCCESS:
            return 1
        print(f"out: {out_f}")
        return 0

    if args.command == "fit-info":
        from bios_recovery.core.bios_analyzer import BiosAnalyzer
        from bios_recovery.platforms.intel.me.fit_bridge import compatible_with_me, probe_tool
        from bios_recovery.platforms.intel.me.fit_versions import tool_for_me_version

        me = BiosAnalyzer().analyze(f).me_version
        match = tool_for_me_version(me)
        print(f"ME version:   {me or 'n/a'}")
        print(
            f"tool release: {match.release or 'none'} [{match.confidence}]"
            + (f" - {match.note}" if match.note else "")
        )
        tool_paths = [args.tool] if args.tool else []
        if not tool_paths:
            from bios_recovery.core import user_library as lib
            from bios_recovery.platforms.intel.me.fit_bridge import ToolProbe
            from bios_recovery.platforms.intel.me.fit_bridge import compatible_with_me as _ok

            for t in lib.scan().tools:
                if (
                    t.identified
                    and _ok(
                        ToolProbe(path=t.path, identified=True, family=t.family, version=t.version),
                        me,
                    )[0]
                ):
                    tool_paths.append(t.path)
            if not tool_paths:
                print(
                    "tool:         none in your library matches this image "
                    "(add folders with: library add-folder PATH)"
                )
                return 0
        for tool_path in tool_paths:
            probe = probe_tool(tool_path)
            if not probe.identified:
                print(f"tool:         refused - {probe.error}")
                return 4
            ok, why = compatible_with_me(probe, me)
            print(f"tool:         {probe.family} {probe.version} {probe.platform}".rstrip())
            for w in probe.warnings:
                print(f"  warning:    {w}")
            print(f"compatible:   {'yes' if ok else 'no'} - {why}")
            return 0 if ok else 4
        return 0

    if args.command == "ec-scan":
        from bios_recovery.platforms.ec.ec_patcher import ECPatcher

        p_ = ECPatcher()
        if p_.load_error:
            print(f"Error: {p_.load_error}", file=sys.stderr)
            return 1
        try:
            hits = p_.scan_patch_sites(f)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        found = [h for h in hits if h.get("found")]
        print(f"EC patches in table: {len(hits)}  (signatures present: {len(found)})")
        for h in hits:
            if h.get("found"):
                print(
                    f"  {h['key']:32s} {h['vendor']:12s} gen={h['generation']:24s} "
                    f"verified={h['verified']} offsets={','.join(h['offsets'])}"
                )
        return 0

    return 1


# CLI command -> tool name in core/traits_matrix.py (same gate as the GUI tabs)
_CLI_TOOL_FOR_COMMAND = {
    "me-clean": "ME Cleaner",
    "recover-passwords": "Dell DVAR Recovery",
    "ec-scan": "EC Patching",
    "ec-extract": "EC Patching",
}

_CLI_COMMANDS = {
    "analyze",
    "extract",
    "graft",
    "capsule",
    "me-clean",
    "remove-passwords",
    "recover-passwords",
    "dmi",
    "set-dmi",
    "ec-extract",
    "ec-scan",
    "fit-info",
}


_CLI_HELP = """usage: bios-recovery <command> FILE [options]
       bios-recovery verify-rebuild ORIGINAL CANDIDATE
       bios-recovery library {add-folder PATH | remove-folder PATH | list | scan | identify FILE}
       bios-recovery --help

With no arguments the graphical application starts.

commands: analyze, extract, graft, capsule, me-clean, remove-passwords,
          recover-passwords, dmi, set-dmi, ec-extract, ec-scan, fit-info

exit codes: 0 success; 1 operation failed or was refused;
            2 usage error or file not found; 3 refused: image not accepted by
              verify-rebuild, or the tool does not apply to this image (use --force);
            4 fit-info: tool refused or incompatible
"""

# Qt's own command-line options, which the GUI accepts.
_QT_OPTIONS = {
    "-platform",
    "-platformpluginpath",
    "-plugin",
    "-style",
    "-stylesheet",
    "-geometry",
    "-font",
    "-display",
    "-session",
    "-reverse",
    "-widgetcount",
    "-qmljsdebugger",
}


def main():
    # --mea-child with bare arguments (no -skip/-exit/-json/-duc/-out) falls into
    # MEA's interactive prompt and fails with EOF; the bridge always passes the
    # full flag set, so this path is only reachable by manual invocation.
    if len(sys.argv) > 1:
        _ensure_streams()
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help", "help"):
        print(_CLI_HELP)
        return 0
    # A bare word that is not a command and not an existing path is a typo: refuse it
    # rather than silently opening the GUI. Existing paths (e.g. a file opened from
    # Explorer) still start the GUI. So does a Qt option; any other flag is refused.
    if len(sys.argv) > 1 and sys.argv[1].startswith("-"):
        if sys.argv[1].split("=", 1)[0] not in _QT_OPTIONS:
            print(f"Error: unknown option '{sys.argv[1]}'\n\n{_CLI_HELP}", file=sys.stderr)
            return 2
    elif (
        len(sys.argv) > 1
        and sys.argv[1] not in (_CLI_COMMANDS | {"verify-rebuild", "library"})
        and not os.path.exists(sys.argv[1])
    ):
        print(f"Error: unknown command '{sys.argv[1]}'\n\n{_CLI_HELP}", file=sys.stderr)
        return 2
    # CLI mode: `bios-recovery <command> FILE [...]` (no Qt involved)
    if len(sys.argv) > 1 and sys.argv[1] == "verify-rebuild":
        return _verify_rebuild_cli(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "library":
        return _library_cli(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] in _CLI_COMMANDS:
        return _cli_main(sys.argv[1:])
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        print(_diagnose_qt_import_failure(exc), file=sys.stderr)
        return 1

    from bios_recovery.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("BIOS Recovery Suite")
    app.setOrganizationName("BIOSRecoverySuite")
    app.setStyle("Fusion")

    from bios_recovery.gui.styles import apply_stylesheet

    apply_stylesheet(app)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main() or 0)
