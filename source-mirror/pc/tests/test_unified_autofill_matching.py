from core.autofill_sources import shares_matching_word
from core.browser_autofill import matching_entries, word_matching_entries
from core.models import Entry


def test_normalization_and_meaningful_containment():
    for left, right in [('ＦｏｏBar', 'foo'), ('微信账号', '微信'), ('WeChatLogin', 'wechat')]:
        assert shares_matching_word(left, right)
    for left, right in [('邮箱', '邮箱登录'), ('login', 'login account'), ('pay', 'repayment'), ('foo', 'food')]:
        assert not shares_matching_word(left, right)


def test_module_binding_and_password_are_eligible():
    entry = Entry(title='Bound', fields={'modules': [
        {'id':'url', 'type':'url', 'value':'https://login.example.com'},
        {'id':'account', 'type':'login_account', 'value': {'password':'secret'}}]})
    assert matching_entries([entry], 'https://login.example.com') == [entry]


def test_sibling_domain_is_only_suggestion():
    entry = Entry(title='Unrelated', password='secret', url='https://a.example.com')
    assert not matching_entries([entry], 'https://b.example.com')
    assert word_matching_entries([entry], 'https://b.example.com') == [entry]


def test_confirmed_web_binding_is_exact_only_for_bound_port():
    entry = Entry(title='Other', password='p', fields={'_autofill_bindings': [
        {'kind':'web', 'host':'example.com', 'origin':'https://example.com:8443'}]})
    assert matching_entries([entry], 'https://example.com:8443') == [entry]
    assert not matching_entries([entry], 'https://example.com')


def test_shared_name_vectors():
    import json
    import os
    from pathlib import Path
    path = Path(os.environ.get('VAULT_SHARED_SPEC_DIR', 'spec')) / 'autofill_matching_v2_fixtures.json'
    for case in json.loads(path.read_text(encoding='utf-8'))['name_pairs']:
        assert shares_matching_word(case['left'], case['right']) == case['expected'], case['id']


def test_exact_and_name_candidates_are_concurrent(tmp_path):
    from core.storage import Vault
    from core.browser_host import BrowserAutofillController
    vault = Vault.create(tmp_path / 'concurrent.pmv', 'master')
    exact = Entry(title='Z exact', password='p', url='https://example.com')
    name = Entry(title='Example account', password='p')
    vault.add(exact)
    vault.add(name)
    assert [e.id for e in BrowserAutofillController._candidate_matches(vault, 'https://example.com')] == [exact.id, name.id]
    vault.close()


def test_remember_is_explicit_and_revision_checked(tmp_path):
    from core.storage import Vault
    from core.browser_host import BrowserAutofillController, FillSelection, SaveSelection
    from core.browser_autofill import BrowserRequest
    path = tmp_path / 'remember.pmv'
    vault = Vault.create(path, 'master')
    entry = Entry(title='Example', password='p')
    vault.add(entry)
    vault.close()
    controller = BrowserAutofillController(lambda: Vault.open(path, 'master'), lambda *a: SaveSelection('cancel'),
        confirm_word_match=lambda *a: FillSelection(True, True), lock_after_seconds=lambda:60)
    assert controller.handle(BrowserRequest('r','get',origin='https://example.com',credential_id=entry.id))['password'] == 'p'
    controller.close()
    reopened = Vault.open(path,'master')
    assert matching_entries([reopened.read_entry(entry.id)],'https://example.com')
    reopened.close()


def test_native_unknown_controls_are_not_guessed():
    from core.native_autofill import FieldInfo, choose_fields, classify_field
    unknown = FieldInfo(object(), 'unknown', focused=True)
    password = FieldInfo(object(), 'password', top=20)
    assert choose_fields([unknown, password]) == (None, password)
    assert classify_field(automation_id='Ｐａｓｓｗｏｒｄ') == 'password'
    assert classify_field(automation_id='postalCode') == 'postal_code'


def test_native_explicit_custom_role_is_supported(monkeypatch):
    from core.native_autofill import WindowsUiaBackend, NativeTarget, PreparedFill
    backend = WindowsUiaBackend()
    sent = []
    monkeypatch.setattr(backend, '_send_focused_text', lambda target, value: sent.append(value))
    result = backend.fill_focused(PreparedFill(NativeTarget(1,2,'app.exe'),()), 'value', role='custom_secret')
    assert result.additional_roles == ('custom_secret',)
    assert sent == ['value']


def test_mapping_rejects_unavailable_role_before_prompt(tmp_path):
    import pytest
    from core.storage import Vault
    from core.browser_host import BrowserAutofillController, SaveSelection
    from core.browser_autofill import BrowserRequest, ProtocolError
    path = tmp_path / 'map.pmv'
    vault = Vault.create(path,'master')
    entry = Entry(title='Example', password='p', url='https://example.com')
    vault.add(entry)
    vault.close()
    prompts = []
    controller = BrowserAutofillController(lambda:Vault.open(path,'master'), lambda *a:SaveSelection('cancel'),
        confirm_field_mapping=lambda *a:prompts.append(a) or True, lock_after_seconds=lambda:60)
    with pytest.raises(ProtocolError) as error:
        controller.handle(BrowserRequest('r','map_field',origin='https://example.com',credential_id=entry.id,
            field_key='name:phone',field_role='phone'))
    assert error.value.code == 'INVALID_REQUEST'
    assert prompts == []
    controller.close()


def test_confirmed_reason_and_naked_binding():
    from core.browser_autofill import browser_match_reason
    naked = Entry(password='p',url='example.com/login')
    assert browser_match_reason(naked,'https://example.com') == 'exact'
    confirmed = Entry(password='p',fields={'_autofill_bindings':[{'kind':'web','host':'example.com'}]})
    assert browser_match_reason(confirmed,'https://example.com') == 'confirmed'
    assert browser_match_reason(confirmed,'https://example.com:8443') == 'same_site'


def test_login_with_only_nonlogin_link_is_candidate(tmp_path):
    from core import autofill_sources as sources, native_autofill
    from core.models import SecretType
    from core.storage import Vault
    from core.browser_host import BrowserAutofillController, SaveSelection
    from core.browser_autofill import BrowserRequest
    path = tmp_path / 'linked-api.pmv'
    vault = Vault.create(path, 'master')
    api = Entry(title='API source',secret_type=SecretType.API_KEY,fields={'api_secret':'sensitive'})
    vault.add(api)
    login = Entry(title='Example',url='https://example.com',target_app='example.exe',fields=sources.encode_links_into_fields({},[
        sources.AutofillLink('link',api.id,(sources.AutofillFieldRef(None,'api_secret','api_secret',True),))]))
    vault.add(login)
    assert [e.id for e in BrowserAutofillController._matches(vault,'https://example.com')] == [login.id]
    assert [e.id for e in BrowserAutofillController._candidate_matches(vault,'https://example.com')] == [login.id]
    assert [e.id for e in native_autofill.matching_vault_entries(vault,'example.exe')] == [login.id]
    vault.close()
    controller = BrowserAutofillController(lambda:Vault.open(path,'master'),lambda *a:SaveSelection('cancel'),lock_after_seconds=lambda:60)
    results=controller.handle(BrowserRequest('r','list',origin='https://example.com',query='Example'))
    assert [e['id'] for e in results['credentials']] == [login.id]
    assert controller.handle(BrowserRequest('r','get',origin='https://example.com',credential_id=login.id))['fields']['api_secret'] == 'sensitive'
    controller.close()

