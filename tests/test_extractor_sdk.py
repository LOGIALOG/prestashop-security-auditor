import pytest

from backend.app.advisories import correlate
from backend.app.extractor_sdk import ExtractionContext, ExtractorPluginError, PluginSignal, run_extractor_plugins
from backend.app.models import Status


class SamplePlugin:
    plugin_id = "community.sample-module"
    api_version = "1.0"

    def extract(self, context: ExtractionContext):
        token = "samplemodule"
        start = context.body.index(token)
        return [PluginSignal(kind="active_module",name=token,confidence="medium",method="data-marker",start=start,end=start+len(token))]


def test_plugin_signal_is_redacted_hashed_namespaced_and_unversioned():
    body = "token=secret123 samplemodule"
    item = run_extractor_plugins("https://shop.test/?token=secret123",body,"text/html",[SamplePlugin()])[0]

    assert item.name == "samplemodule"
    assert item.version is None
    assert item.evidence.detection_method == "plugin:community.sample-module:data-marker"
    assert "secret123" not in item.evidence.url
    assert len(item.evidence.response_sha256) == 64


def test_plugin_module_signal_cannot_confirm_an_advisory_version():
    class AdvisoryPlugin(SamplePlugin):
        plugin_id = "community.ybc-blog"

        def extract(self, context):
            return [{"kind":"active_module","name":"ybc_blog","confidence":"medium","method":"marker","start":0,"end":8}]

    finding = correlate(run_extractor_plugins("https://shop.test/","ybc_blog","text/html",[AdvisoryPlugin()]))[0]
    assert finding.status == Status.REQUIRES_ACCESS
    assert finding.version is None


@pytest.mark.parametrize("plugin",[
    type("BadId",(),{"plugin_id":"Bad ID","api_version":"1.0","extract":lambda self,context:[]})(),
    type("BadVersion",(),{"plugin_id":"community.bad-version","api_version":"2.0","extract":lambda self,context:[]})(),
    type("BadRange",(),{"plugin_id":"community.bad-range","api_version":"1.0","extract":lambda self,context:[{"kind":"theme","name":"classic","method":"marker","start":0,"end":999}]})(),
])
def test_invalid_plugin_contract_stops_the_audit(plugin):
    with pytest.raises(ExtractorPluginError):
        run_extractor_plugins("https://shop.test/","classic","text/html",[plugin])


def test_duplicate_plugin_ids_are_rejected():
    with pytest.raises(ExtractorPluginError,match="dupliqué"):
        run_extractor_plugins("https://shop.test/","samplemodule","text/html",[SamplePlugin(),SamplePlugin()])
