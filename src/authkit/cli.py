"""Command line: key management, admin creation, demo data, maintenance."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from sqlalchemy import select

from authkit.app import build_context
from authkit.config import ConfigError, Settings
from authkit.db import create_schema, make_engine
from authkit.errors import ApiError
from authkit.models import User
from authkit.security import keys
from authkit.security.breach import build_sorted_hash_file
from authkit.services import accounts, audit, maintenance, sessions
from authkit.services.audit import RequestInfo

DEMO_USERS = [
    ("admin@example.com", "admin", "demo-admin-passphrase-2026"),
    ("amina@example.com", "user", "demo-amina-passphrase-2026"),
]


def _open(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings.database_url)
    create_schema(engine)
    return build_context(settings, engine)


def cmd_init_keys(args: argparse.Namespace) -> None:
    path = Settings().keys_file
    if path.exists():
        raise ConfigError(f"{path} already exists; use rotate-key to add a signing key")
    keys.write_document(path, keys.Secrets.generate_document(args.alg))
    print(f"wrote {path} (mode 600). Back it up; losing it invalidates 2FA secrets.")


def cmd_rotate_key(args: argparse.Namespace) -> None:
    kid = keys.rotate_jwt_key(Settings().keys_file, args.alg)
    print(f"new active signing key: {kid}. Old keys still verify until you run prune-keys.")


def cmd_prune_keys(args: argparse.Namespace) -> None:
    removed = keys.prune_jwt_keys(Settings().keys_file, args.keep)
    print(f"removed keys: {', '.join(removed) or 'none'}")


def cmd_create_admin(args: argparse.Namespace) -> None:
    settings = Settings()
    ctx = _open(settings)
    password = os.environ.get("AUTHKIT_ADMIN_PASSWORD") or getpass.getpass("Password: ")
    email = accounts.normalize_email(args.email)
    accounts.check_new_password(ctx, password, email)
    now = ctx.clock.now()
    with ctx.sessions() as db:
        if db.scalar(select(User).where(User.email == email)):
            raise ConfigError(f"{email} already exists")
        db.add(
            User(
                email=email,
                password_hash=ctx.hasher.hash(password),
                role="admin",
                email_verified_at=now,
                password_changed_at=now,
                created_at=now,
            )
        )
        db.commit()
    print(f"created admin {email}")


def cmd_seed_demo(_: argparse.Namespace) -> None:
    settings = Settings()
    if settings.env == "production":
        raise ConfigError("seed-demo refuses to run with AUTHKIT_ENV=production")
    ctx = _open(settings)
    now = ctx.clock.now()
    with ctx.sessions() as db:
        for email, role, password in DEMO_USERS:
            if db.scalar(select(User).where(User.email == email)):
                continue
            user = User(
                email=email,
                password_hash=ctx.hasher.hash(password),
                role=role,
                email_verified_at=now,
                password_changed_at=now,
                created_at=now,
            )
            db.add(user)
            db.flush()
            if role == "user":
                for ip, ua in (
                    ("203.0.113.24", "Mozilla/5.0 (Linux; Android 14) Firefox/131.0 Mobile"),
                    ("198.51.100.7", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Safari/604.1"),
                ):
                    req = RequestInfo(ip, ua)
                    t = sessions.start_session(ctx, db, user, req, used_2fa=False)
                    audit.record(
                        ctx,
                        db,
                        audit.LOGIN_SUCCESS,
                        req,
                        user_id=user.id,
                        session_id=t.session_id,
                        method="password",
                    )
                bad = RequestInfo("192.0.2.99", "curl/8.7.1")
                for _i in range(3):
                    audit.record(ctx, db, audit.LOGIN_FAILURE, bad, user_id=user.id, email=email)
        db.commit()
    print("demo accounts (synthetic, local use only):")
    for email, role, password in DEMO_USERS:
        print(f"  {role:5} {email}  /  {password}")


def cmd_breach_build(args: argparse.Namespace) -> None:
    words = Path(args.wordlist).read_text().splitlines()
    n = build_sorted_hash_file([w.strip() for w in words], Path(args.output))
    print(f"wrote {n} sorted SHA-1 lines to {args.output}")


def cmd_purge(_: argparse.Namespace) -> None:
    ctx = _open(Settings())
    with ctx.sessions() as db:
        print(maintenance.purge(ctx, db))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="authkit")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn, help_ in (
        ("init-keys", cmd_init_keys, "create the key file (JWT key, data key, pepper)"),
        ("rotate-key", cmd_rotate_key, "add a new active JWT signing key"),
        ("prune-keys", cmd_prune_keys, "drop old JWT keys"),
    ):
        sp = sub.add_parser(name, help=help_)
        if name != "prune-keys":
            sp.add_argument("--alg", choices=["EdDSA", "HS256"], default="EdDSA")
        else:
            sp.add_argument("--keep", type=int, default=2)
        sp.set_defaults(func=fn)
    sp = sub.add_parser("create-admin", help="create an admin (password from prompt or env)")
    sp.add_argument("--email", required=True)
    sp.set_defaults(func=cmd_create_admin)
    sub.add_parser(
        "seed-demo", help="create synthetic demo accounts (not for production)"
    ).set_defaults(func=cmd_seed_demo)
    sp = sub.add_parser("breach-build", help="build a sorted SHA-1 file from a word list")
    sp.add_argument("wordlist")
    sp.add_argument("output")
    sp.set_defaults(func=cmd_breach_build)
    sub.add_parser("purge", help="delete expired rows").set_defaults(func=cmd_purge)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ApiError as exc:
        reasons = ", ".join(exc.extra.get("reasons", []))
        print(f"error: {exc.message} {reasons}".strip(), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
