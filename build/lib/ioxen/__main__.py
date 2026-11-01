import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="ioxen",
        description="iOS runtime interception tool. Uses Frida to hook IPC entry points (XPC/NSXPC, URL schemes, Darwin notifications) and inspect app attack-surface events in real time.",
    )
    p_proj = parser.add_mutually_exclusive_group()
    p_proj.add_argument(
        "--project",
        metavar="FILE",
        help="Open an existing project database (.ioxen, or .noxen from noxen) and restore its history",
    )
    p_proj.add_argument(
        "--new-project",
        metavar="NAME",
        dest="new_project",
        help="Create a new project database with the given name (e.g. 'my_app')",
    )
    args = parser.parse_args()
    from ioxen.app import IoxenApp
    try:
        app = IoxenApp(args)
    except (FileNotFoundError, FileExistsError) as exc:
        print(f"ioxen: {exc}", file=sys.stderr)
        return 1
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
