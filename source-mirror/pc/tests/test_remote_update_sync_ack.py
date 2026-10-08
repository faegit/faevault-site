from types import SimpleNamespace
from core import auto_cloud_sync
from core.storage import VaultLineage
from core.remote_update import metadata_version


def test_same_revision_acknowledges_authenticated_download_not_later_metadata():
    observed=SimpleNamespace(exists=True,size=100,modified_at=123.0,revision='"version-a"')
    class Vault:
        pmve_identity=object()
        def authenticate_external_file(self,path): return self.pmve_identity
        def classify_lineage(self,left,right): return VaultLineage.SAME
    def download(path): return SimpleNamespace(path=path,**observed.__dict__)
    result=auto_cloud_sync._sync_pmve_files(Vault(),'webdav',download,lambda *args:None)
    assert result.stats['remote_update_version']==metadata_version('webdav',observed)

    assert result.stats["remote_update_consumed_version"] == metadata_version("webdav", observed)
