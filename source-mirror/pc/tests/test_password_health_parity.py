from core.password_health import _extremely_weak


def test_zxcvbn_catches_dictionary_variants_missed_by_character_classes():
    assert _extremely_weak("Summer2019")
    assert _extremely_weak("Passw0rd!")
    assert _extremely_weak("Company123")
    assert not _extremely_weak("correct horse battery staple")
