"""Reset the local administrator password from the host operating system."""

from getpass import getpass

from backend.services.auth_service import AuthenticationInputError, auth_service


def main() -> None:
    username = input("Administrator username: ").strip()
    password = getpass("New administrator password: ")
    confirmation = getpass("Confirm new password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    try:
        auth_service.recover_password(username, password)
    except (AuthenticationInputError, LookupError) as exc:
        raise SystemExit(str(exc)) from exc
    print("Administrator password updated. All existing sessions were revoked.")


if __name__ == "__main__":
    main()
