from image_poc.server import STATIC_ROOT


def test_hidden_preview_image_overrides_block_display():
    html = (STATIC_ROOT / "index.html").read_text()
    css = (STATIC_ROOT / "styles.css").read_text()
    js = (STATIC_ROOT / "app.js").read_text()

    assert '<img id="outputImage" alt="Generated image preview" hidden>' in html

    preview_rule_start = css.index(".preview img {")
    hidden_rule_start = css.index(".preview img[hidden] {")
    hidden_rule_end = css.index("}", hidden_rule_start)
    hidden_rule = css[hidden_rule_start:hidden_rule_end]

    assert hidden_rule_start > preview_rule_start
    assert "display: none;" in hidden_rule
    assert 'imageEl.style.display = "none";' in js
    assert 'imageEl.style.display = "";' in js


def test_static_ui_loads_mode_from_health_without_credentials():
    html = (STATIC_ROOT / "index.html").read_text()
    js = (STATIC_ROOT / "app.js").read_text()

    assert '<span class="mode-badge" id="modeBadge">gateway-dnsid</span>' in html
    assert 'fetch("/api/health"' in js
    assert "modeBadge.textContent = currentAuthMode;" in js
    assert "Authorization" not in js
    assert "Bearer" not in js
