def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    return singular if abs(count) == 1 else plural_form or f"{singular}s"
