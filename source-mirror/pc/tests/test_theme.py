from ui import theme


def test_resolve_mode_keeps_explicit_modes_and_resolves_system():
    assert theme.resolve_mode("auto", system_dark=False) == "light"
    assert theme.resolve_mode("auto", system_dark=True) == "dark"
    # 旧版“品牌蓝”与未知值都回退到浅色
    assert theme.resolve_mode("brand_blue") == "light"
    assert theme.resolve_mode("unknown") == "light"


def test_light_palette_separates_control_and_text_tones():
    assert theme.LIGHT["bg"] == "#F7F9FC"
    assert theme.LIGHT["surface"] == "#FFFFFF"
    assert theme.LIGHT["surface_alt"] == "#F2F5FA"
    assert theme.LIGHT["text"] == "#1F2937"
    assert theme.LIGHT["accent"] == "#47669A"
    assert theme.LIGHT["accent_hover"] == "#3C5B8D"
    assert theme.LIGHT["accent_soft"] == "#EEF2F8"
    assert theme.LIGHT["accent_text"] == "#2F6FED"
    assert theme.LIGHT["accent_text_hover"] == "#1D4FB8"
    assert theme.LIGHT["border"] == "#DCE3EF"


def test_only_light_primary_button_uses_navy_gradient():
    light = theme.stylesheet("light")
    assert "qlineargradient" in light
    assert "#4B6A9D" in light
    assert "#3F5E8F" in light
    assert "color: #2F6FED" in light
    assert "border-color: #47669A" in light
    assert "qlineargradient" not in theme.stylesheet("dark")
