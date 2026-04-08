"""Authentication commands: login, status, logout."""

import time

import click

from ..client import XhsClient
from ..command_normalizers import normalize_xhs_user_payload
from ..cookies import clear_cookies, get_cookies, get_browser_cookie_path, get_cookie_path, _resolve_effective_path
from ..exceptions import XhsApiError
from ..formatter import (
    console,
    maybe_print_structured,
    print_success,
    render_user_info,
    success_payload,
)
from ._common import handle_errors, run_client_action, structured_output_options


def _emit_payload(data: dict[str, object], *, as_json: bool, as_yaml: bool) -> bool:
    """Emit a structured success payload when requested."""
    return maybe_print_structured(success_payload(data), as_json=as_json, as_yaml=as_yaml)


def _is_valid_login(user: dict[str, object]) -> bool:
    """Check whether the normalized user payload represents a real logged-in session."""
    if user.get("guest"):
        return False
    nickname = user.get("nickname", "")
    return bool(nickname and nickname != "Unknown")


def _print_login_success(user: dict[str, object]) -> None:
    """Print a concise login success message."""
    print_success(f"Logged in as: {user['nickname']} (ID: {user['red_id']})")


def _print_status_summary(user: dict[str, object]) -> None:
    """Render a short authenticated-user summary."""
    console.print("[bold green]✓ Logged in[/bold green]")
    console.print(f"  昵称: [bold]{user['nickname']}[/bold]")
    if user["red_id"]:
        console.print(f"  小红书号: {user['red_id']}")
    if user["ip_location"]:
        console.print(f"  IP 属地: {user['ip_location']}")
    if user["desc"]:
        console.print(f"  简介: {user['desc']}")

@click.command()
@click.option(
    "--cookie-source",
    type=str,
    default=None,
    help="Browser to read cookies from (default: auto-detect all installed browsers)",
)
@structured_output_options
@click.option("--qrcode", "use_qrcode", is_flag=True, default=False,
              help="Login via QR code (scan with Xiaohongshu app)")
@click.pass_context
def login(ctx, cookie_source: str | None, as_json: bool, as_yaml: bool, use_qrcode: bool):
    """Log in by extracting cookies from browser, or via QR code."""

    if use_qrcode:
        def _login_with_qrcode() -> None:
            from ..qr_login import qrcode_login
            from ..cookies import _resolve_effective_path

            raw_source = cookie_source or (ctx.obj.get("cookie_source", "auto") if ctx.obj else "auto")
            raw_file = ctx.obj.get("cookies_file") if ctx.obj else None
            effective_path = _resolve_effective_path(raw_source, raw_file)

            cookies = qrcode_login(prefer_browser_assisted=True, cookie_path=effective_path)

            # Verify by fetching user info (may return guest=true briefly)
            import time
            time.sleep(1)  # brief delay for session propagation
            with XhsClient(cookies) as client:
                info = client.get_self_info()
            user = normalize_xhs_user_payload(info)

            if user["guest"]:
                # Session not yet propagated; still valid
                if not _emit_payload(
                    {"authenticated": True, "user": {"id": user["id"]}},
                    as_json=as_json,
                    as_yaml=as_yaml,
                ):
                    print_success("Logged in (session saved)")
            else:
                if not _emit_payload({"authenticated": True, "user": user}, as_json=as_json, as_yaml=as_yaml):
                    _print_login_success(user)

        handle_errors(
            _login_with_qrcode,
            as_json=as_json,
            as_yaml=as_yaml,
            prefix="QR login failed",
        )
        return

    # Browser cookie extraction (default)
    if cookie_source is None:
        cookie_source = ctx.obj.get("cookie_source", "auto") if ctx.obj else "auto"
    cookies_file = ctx.obj.get("cookies_file") if ctx.obj else None

    def _login_with_browser() -> None:
        browser, cookies = get_cookies(cookie_source, force_refresh=True, cookies_file=cookies_file)
        from ..cookies import _resolve_effective_path, get_cookie_path as _default_path
        saved_to = _resolve_effective_path(cookie_source, cookies_file)
        if saved_to is None:
            from ..cookies import get_browser_cookie_path
            saved_to = get_browser_cookie_path(browser) if browser != "saved" else _default_path()
        print_success(f"Cookies extracted from {browser} → {saved_to}")

        # Verify by fetching user info, retry once if session not yet propagated
        with XhsClient(cookies) as client:
            info = client.get_self_info()
        user = normalize_xhs_user_payload(info)

        if not _is_valid_login(user):
            time.sleep(2.5)
            with XhsClient(cookies) as client:
                info = client.get_self_info()
            user = normalize_xhs_user_payload(info)

        if not _is_valid_login(user):
            raise XhsApiError(
                "Browser cookies were extracted, but the session appears invalid "
                "(guest or incomplete profile). Try: xhs login --qrcode"
            )

        if not _emit_payload({"authenticated": True, "user": user}, as_json=as_json, as_yaml=as_yaml):
            _print_login_success(user)

    handle_errors(
        _login_with_browser,
        as_json=as_json,
        as_yaml=as_yaml,
        prefix="Login verification failed",
    )


@click.command()
@structured_output_options
@click.pass_context
def status(ctx, as_json: bool, as_yaml: bool):
    """Check current login status and user info."""
    def _show_status() -> None:
        info = run_client_action(ctx, lambda client: client.get_self_info())
        user = normalize_xhs_user_payload(info)

        if not _emit_payload({"authenticated": True, "user": user}, as_json=as_json, as_yaml=as_yaml):
            _print_status_summary(user)

    handle_errors(_show_status, as_json=as_json, as_yaml=as_yaml, prefix="Status check failed")


@click.command()
@structured_output_options
@click.option("--all", "clear_all", is_flag=True, default=False,
              help="Remove ALL cookie files (default + all browser-specific *_cookies.json).")
@click.pass_context
def logout(ctx, as_json: bool, as_yaml: bool, clear_all: bool):
    """Clear saved cookies and log out."""
    from ..cookies import _resolve_effective_path
    raw_source = ctx.obj.get("cookie_source", "auto") if ctx.obj else "auto"
    raw_file = ctx.obj.get("cookies_file") if ctx.obj else None
    cookie_path = _resolve_effective_path(raw_source, raw_file)
    removed = clear_cookies(cookie_path, all_cookies=clear_all)
    payload = {"logged_out": True, "cleared": [str(p) for p in removed]}
    if not _emit_payload(payload, as_json=as_json, as_yaml=as_yaml):
        if clear_all:
            if removed:
                print_success(f"Logged out — cleared {len(removed)} cookie file(s): " + ", ".join(p.name for p in removed))
            else:
                print_success("Logged out — no cookie files found")
        else:
            target = str(cookie_path) if cookie_path else "default cookies"
            print_success(f"Logged out — {target} cleared")


@click.command()
@structured_output_options
@click.pass_context
def whoami(ctx, as_json: bool, as_yaml: bool):
    """Show detailed profile of current user (level, fans, likes)."""
    def _show_profile() -> None:
        info = run_client_action(ctx, lambda client: client.get_self_info())
        user = normalize_xhs_user_payload(info)

        if not _emit_payload({"user": user}, as_json=as_json, as_yaml=as_yaml):
            render_user_info(info)

    handle_errors(_show_profile, as_json=as_json, as_yaml=as_yaml, prefix="Failed to get profile")
