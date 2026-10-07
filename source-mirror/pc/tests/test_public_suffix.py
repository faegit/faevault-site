from core.public_suffix import registrable_domain


def test_private_and_multilabel_boundaries():
    assert registrable_domain('a.example.co.uk') == 'example.co.uk'
    assert registrable_domain('a.alice.github.io') == 'alice.github.io'
    assert registrable_domain('bob.github.io') == 'bob.github.io'
    assert registrable_domain('a.alice.blogspot.com') == 'alice.blogspot.com'
    assert registrable_domain('co.uk') is None


def test_psl_wildcard_exception():
    assert registrable_domain('a.b.ck') == 'a.b.ck'
    assert registrable_domain('b.ck') is None
    assert registrable_domain('a.www.ck') == 'www.ck'


def test_browser_sibling_site_is_suggestion_and_private_tenants_separate():
    from core.browser_autofill import browser_match_reason, matching_entries
    from core.models import Entry
    entry = Entry(title='Unrelated', password='p', url='https://a.example.co.uk')
    assert browser_match_reason(entry,'https://b.example.co.uk') == 'same_site'
    assert not matching_entries([entry],'https://b.example.co.uk')
    tenant = Entry(title='Unrelated',password='p',url='https://alice.github.io')
    assert browser_match_reason(tenant,'https://bob.github.io') != 'same_site'
