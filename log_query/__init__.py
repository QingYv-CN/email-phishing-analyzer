from log_query.common import (
    LOG_BASE_URL, BANNED_EXTENSIONS,
    _get_log_token, _extract_email, _get_domain,
    _is_whitelist_mailfrom, _contains_internal_domain,
    _normalize_url, _extract_urls_from_href, _random_sample,
)