"""Domain-to-application classification.

The mapping is data (a dict), not scattered if/elif chains, so adding a new
recognized application means adding a table entry, not touching control
flow elsewhere in the codebase.

Matching is suffix-based against registrable-ish domain components (e.g.
"www.youtube.com" and "m.youtube.com" both match a "youtube.com" entry),
which is a deliberate simplification -- a production classifier would use
a public-suffix-list-aware match to avoid false positives like
"notyoutube.com".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dpi.models import AppType

DEFAULT_DOMAIN_APP_MAP: dict[str, AppType] = {
    "youtube.com": AppType.YOUTUBE,
    "googlevideo.com": AppType.YOUTUBE,  # YouTube's video CDN domain
    "facebook.com": AppType.FACEBOOK,
    "fbcdn.net": AppType.FACEBOOK,
    "github.com": AppType.GITHUB,
    "githubusercontent.com": AppType.GITHUB,
    "google.com": AppType.GOOGLE,
    "grammarly.io": AppType.GRAMMARLY,
    "grammarly.com": AppType.GRAMMARLY,
}


@dataclass
class DomainClassifier:
    """Classifies a domain name into an AppType using a configurable
    suffix-match table.

    Example:
        classifier = DomainClassifier()
        classifier.classify("m.youtube.com")  # -> AppType.YOUTUBE
        classifier.classify("example.org")     # -> AppType.UNKNOWN
    """

    domain_app_map: dict[str, AppType] = field(
        default_factory=lambda: dict(DEFAULT_DOMAIN_APP_MAP)
    )

    def classify(self, domain: str | None) -> AppType:
        """Return the AppType for a domain, or UNKNOWN if unrecognized or
        if ``domain`` is None (i.e. no domain could be extracted at all)."""
        if not domain:
            return AppType.UNKNOWN

        normalized = domain.lower().strip().rstrip(".")

        for known_suffix, app in self.domain_app_map.items():
            if normalized == known_suffix or normalized.endswith(
                "." + known_suffix
            ):
                return app

        return AppType.UNKNOWN

    def register(self, domain_suffix: str, app: AppType) -> None:
        """Add or override a domain -> AppType mapping at runtime."""
        self.domain_app_map[domain_suffix.lower()] = app