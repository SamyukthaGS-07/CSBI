"""
Module 2 — Infrastructure Screening & Routing (Stage 1)
Cheap, page-free check: uses only Layer 1 (structural) + Layer 2 (temporal)
features. Decides whether a site can be resolved directly, or must be
escalated to Module 3 (behavioural) + Module 4 (clustering) — Stage 2.
"""

FREE_HOSTING_SUFFIXES = ("pages.dev", "web.app", "github.io", "netlify.app", "vercel.app", "blogspot.com")


def stage1_routing(url: str, features: dict):
    host = url.split("//")[-1].split("/")[0].lower()
    is_free_host = any(host.endswith(suf) for suf in FREE_HOSTING_SUFFIXES)
    age = features.get("domain_age_days", 9999)

    if is_free_host:
        return {
            "is_free_hosting": True, "routed_to_stage2": True,
            "route_reason": "Shared free-hosting platform — certificate & IP belong to "
                             "the platform, not this site. Escalating to Stage 2.",
            "stage1_verdict": None,
        }
    if 0 < age <= 30:
        return {
            "is_free_hosting": False, "routed_to_stage2": False,
            "route_reason": f"Own infrastructure, domain registered only {int(age)} days ago — HIGH risk.",
            "stage1_verdict": "HIGH",
        }
    return {
        "is_free_hosting": False, "routed_to_stage2": False,
        "route_reason": f"Own infrastructure, established domain ({int(age)} days) — LOW risk.",
        "stage1_verdict": "LOW",
    }
