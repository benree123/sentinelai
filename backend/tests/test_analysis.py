import asyncio
from types import SimpleNamespace
import pytest
from app import analysis

@pytest.mark.parametrize('field',['summary','hypotheses','next_steps'])
def test_invalid_model_content_falls_back(monkeypatch,field):
    output={'summary':'Evidence assessment','hypotheses':['Possible activity'],'next_steps':['Verify evidence']}
    output[field]='x'*1501 if field=='summary' else ['x'*501]
    class Response:
        def raise_for_status(self):pass
        def json(self):return {'response':__import__('json').dumps(output)}
    class Client:
        def __init__(self,**kwargs):pass
        async def __aenter__(self):return self
        async def __aexit__(self,*args):pass
        async def post(self,*args,**kwargs):return Response()
    monkeypatch.setenv('OLLAMA_MODEL','test-only-model')
    monkeypatch.setattr(analysis.httpx,'AsyncClient',Client)
    incident=SimpleNamespace(id=1,title='Test signal',rule='AUTH-001',score=70,severity='high',explanation='Rule signal')
    result=asyncio.run(analysis.analyze(incident,[]))
    assert result['mode']=='evidence_briefing'
    assert 'invalid output' in result['limitations']
    assert result['evidence_ids']==[]
