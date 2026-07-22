from __future__ import annotations


def extract_behavioral_features(html: str) -> dict[str, object]:
    lowered = html.lower()
    return {
        "login_mentions": lowered.count("login"),
        "form_mentions": lowered.count("form"),
        "external_link_count": lowered.count("http://") + lowered.count("https://"),
    }
