from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken
from fastapi.testclient import TestClient

from godswork.app import create_app
from godswork.config import Target
from godswork.store import Store, Conflict, Forbidden
from godswork.tools import Tools
from godswork.opencode import ROOT, OpenCode, require_ubuntu_vm


class HarnessTest(unittest.TestCase):
    def setUp(self):
        directory=ROOT/'.tools/data/tests'
        directory.mkdir(parents=True,exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=directory)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.key = Fernet.generate_key()
        self.store = Store(self.path / "state.sqlite", self.key)
        self.store.initialize("captain", "strong-password-123")
        self.linux_token = self.store.enroll("linux-student")
        self.ad_token = self.store.enroll("ad-student")
        self.inventory = {
            "targets": [
                {"id":"linux", "worker":"linux-student", "host":"linux.lab.test", "transport":"ssh", "credential":"linux-admin", "known_hosts":"known_hosts"},
                {"id":"ad", "worker":"ad-student", "host":"dc.lab.test", "transport":"winrm", "port":5986, "credential":"ad-admin", "ca_file":"ca.pem"}],
            "services":[{"id":"ad-auth","target":"ad"},{"id":"linux-login","target":"linux","depends_on":["ad-auth"]},{"id":"nginx","target":"linux"}]}
        self.store.inventory(self.inventory)
        self.store.add_credential("linux-admin", {"target":"linux","username":"labadmin"}, "LinuxOld!123")
        self.store.add_credential("ad-admin", {"target":"ad","username":"LAB\\labadmin","account":"labadmin","rotate":True,
            "rotation_kind":"ad-user","consumers":["linux"],"consumer_usernames":{"linux":"labadmin@lab.test"}}, "ADOld!123")
        self.app = create_app(self.store, insecure_local=True)
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)

    def task(self, resources=None):
        return self.store.create_task("Lab task", "Check, harden, and verify", resources or ["linux"])

    def evidence(self, worker, task, target, purpose="execute", rotation=None):
        operation = self.store.operation_start(worker, task, target, "health check", purpose, rotation)
        self.store.operation_finish(worker, operation, {"exit_code":0,"stdout":"healthy"})
        return operation

    def applied_rotation(self):
        task = self.task(["ad", "linux"])
        self.store.claim("ad-student"); self.store.claim("linux-student")
        rotation = self.store.rotation_begin("ad-student", task["id"], "ad-admin")
        self.store.rotation_step("ad-student", task["id"], rotation["id"], "applying", "ad")
        self.evidence("ad-student", task["id"], "ad", "rotate", rotation["id"])
        self.store.rotation_step("ad-student", task["id"], rotation["id"], "applied", "ad")
        return task, rotation

    def test_simultaneous_claims_and_one_remote_writer(self):
        first = self.task(); second = self.task()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.store.claim, "linux-student") for _ in range(2)]
            results = []
            for future in futures:
                try: results.append(future.result())
                except Conflict: results.append(None)
        self.assertEqual(sum(r is not None for r in results), 1)
        self.assertEqual(self.store.snapshot()["locks"], [{"target":"linux","task":first["id"]}])
        operation = self.store.operation_start("linux-student", first["id"], "linux", "check")
        with self.assertRaises(Conflict):
            self.store.operation_start("linux-student", first["id"], "linux", "other check")
        self.store.operation_finish("linux-student", operation, {"exit_code":0})
        self.store.complete("linux-student", first["id"], "Verified")
        self.assertEqual(self.store.claim("linux-student")["id"], second["id"])

    def test_scope_credentials_and_target_controls(self):
        task = self.task(); self.store.claim("linux-student")
        with self.assertRaises(Forbidden):
            self.store.operation_start("linux-student", task["id"], "ad", "whoami")
        with self.assertRaises(Forbidden):
            self.store.credential("linux-student", task["id"], "ad-admin", "ad")
        with self.assertRaises(Forbidden):
            self.store.credential("linux-student", task["id"], "linux-admin", "ad")
        self.assertEqual(self.store.credential("linux-student", task["id"], "ad-admin", "linux")["password"], "ADOld!123")
        self.store.control("captain", "revoke", "linux-student")
        with self.assertRaises(Forbidden): self.store.authenticate(self.linux_token)
        self.assertEqual(self.store.snapshot()["tasks"][0]["state"], "uncertain")

    def test_expired_worker_cannot_renew_or_release_locks(self):
        task = self.task(); self.store.claim("linux-student")
        with self.store.transaction() as db:
            record = self.store.get(db, "task", task["id"])
            record["participants"]["linux-student"]["deadline"] = time.time() - 1
            self.store.put(db, "task", task["id"], record)
        self.store.heartbeat("linux-student", "late")
        reopened = Store(self.path / "state.sqlite", self.key)
        self.assertEqual(reopened.snapshot()["tasks"][0]["state"], "uncertain")
        self.assertTrue(reopened.snapshot()["locks"])
        with self.assertRaises(Forbidden): reopened.operation_start("linux-student", task["id"], "linux", "check")
        reopened.control("captain", "reconcile", task["id"], "Confirmed no remote commands remain; inspected service.")
        self.assertFalse(reopened.snapshot()["locks"])

    def test_pause_and_uncertain_timeout(self):
        task = self.task(); self.store.claim("linux-student")
        operation = self.store.operation_start("linux-student", task["id"], "linux", "reload")
        self.store.control("captain", "pause")
        with self.assertRaises(Forbidden): self.store.operation_start("linux-student", task["id"], "linux", "again")
        self.store.operation_finish("linux-student", operation, {"error":"timeout"}, uncertain=True)
        self.store.control("captain", "resume")
        self.assertIsNone(self.store.claim("linux-student"))
        self.assertTrue(self.store.snapshot()["locks"])

    def test_full_cross_worker_rotation_and_secret_redaction(self):
        task, rotation = self.applied_rotation()
        pending = self.store.credential("ad-student", task["id"], "ad-admin", "ad", pending=True)["password"]
        with self.assertRaises(Conflict): self.store.rotation_step("ad-student", task["id"], rotation["id"], "commit", "ad")
        for worker, target in (("ad-student", "ad"), ("linux-student", "linux")):
            self.evidence(worker, task["id"], target, "fresh_auth", rotation["id"])
            self.store.rotation_step(worker, task["id"], rotation["id"], "verified", target)
        self.store.rotation_step("ad-student", task["id"], rotation["id"], "commit", "ad")
        with self.assertRaises(Conflict):self.store.rotation_begin("ad-student",task["id"],"ad-admin")
        self.assertEqual(self.store.credential("ad-student", task["id"], "ad-admin", "ad")["password"], pending)
        self.store.message("ad-student", task["id"], "Old ADOld!123 and new " + pending)
        snapshot = json.dumps(self.store.snapshot())
        self.assertNotIn("ADOld!123", snapshot); self.assertNotIn(pending, snapshot)
        self.store.complete("ad-student", task["id"], "Verified")
        self.assertTrue(self.store.snapshot()["locks"])
        self.store.complete("linux-student", task["id"], "Verified")
        self.assertFalse(self.store.snapshot()["locks"])
        self.assertNotIn(pending.encode(), self.path.joinpath("state.sqlite").read_bytes())

    def test_missing_evidence_and_consumer_update_block_commit(self):
        task, rotation = self.applied_rotation()
        with self.assertRaises(Conflict): self.store.rotation_step("linux-student", task["id"], rotation["id"], "verified", "linux")
        with self.assertRaises(Conflict): self.store.rotation_begin("ad-student", task["id"], "ad-admin")
        for worker, target in (("ad-student","ad"),("linux-student","linux")):
            self.evidence(worker, task["id"], target, "fresh_auth", rotation["id"])
            self.store.rotation_step(worker, task["id"], rotation["id"], "verified", target)
        with self.store.transaction() as db:
            c = self.store.get(db,"credential","ad-admin"); c["consumer_updates"]={"linux":"update ${NEW_PASSWORD}"}; self.store.put(db,"credential","ad-admin",c)
        with self.assertRaises(Conflict): self.store.rotation_step("ad-student", task["id"], rotation["id"], "commit", "ad")

    def test_crash_after_password_change_requires_manual_recovery(self):
        task = self.task(["ad","linux"]); self.store.claim("ad-student"); self.store.claim("linux-student")
        rotation = self.store.rotation_begin("ad-student", task["id"], "ad-admin")
        self.store.rotation_step("ad-student", task["id"], rotation["id"], "applying", "ad")
        reopened = Store(self.path / "state.sqlite", self.key)
        with self.assertRaises(Conflict): reopened.rotation_step("ad-student", task["id"], rotation["id"], "applying", "ad")
        reopened.control("captain", "stop", "ad-student")
        with self.assertRaises(Conflict): reopened.control("captain", "reconcile", task["id"], "Inspected")
        reopened.recover_rotation("captain", rotation["id"], True, "Stopped both workers; verified the pending password on issuer and Linux.")
        reopened.control("captain", "reconcile", task["id"], "Confirmed remote quiescence and completed credential recovery.")
        self.assertFalse(reopened.snapshot()["locks"])

    def test_portal_outage_dedup_staleness_and_dependencies(self):
        payload = {"generated_at":time.time(),"services":[{"id":"linux-login","status":"down"}]}
        self.store.observe(payload); self.store.observe(payload)
        snapshot = self.store.snapshot()
        self.assertEqual(len(snapshot["tasks"]),1)
        self.assertEqual(snapshot["tasks"][0]["resources"],["ad","linux"])
        with self.assertRaises(ValueError): self.store.observe(payload | {"generated_at":time.time()-100})
        with self.store.transaction() as db:
            s=self.store.get(db,"service","linux-login");s["source_at"]=time.time()-100;self.store.put(db,"service",s["id"],s)
        self.assertEqual(next(s for s in self.store.snapshot()["services"] if s["id"]=="linux-login")["status"],"stale")

    def test_inject_requires_actual_template_evidence_and_human_submission(self):
        self.store.observe({"generated_at":time.time(),"services":[],"injects":[{"id":"I-1","title":"Health","instructions":"Check nginx","deadline":"today"}]})
        task=self.store.create_task("Inject","Check nginx",["linux"],"inject:I-1",kind="inject")
        self.store.claim("linux-student")
        op=self.evidence("linux-student",task["id"],"linux")
        with self.assertRaises(Conflict): self.store.draft("linux-student",task["id"],"I-1","healthy",[op],"done",None)
        draft=self.store.draft("linux-student",task["id"],"I-1","healthy",[op],"done","$title\n$response\n$evidence\n$checklist")
        self.assertEqual(draft["state"],"needs_review");self.assertIn(op,draft["draft"])

    def test_dashboard_auth_csrf_and_no_secret_leak(self):
        self.assertEqual(self.client.get('/api/state').status_code,403)
        self.assertEqual(self.client.post('/api/login',json={"username":"captain","password":"strong-password-123"}).status_code,200)
        state=self.client.get('/api/state').json()
        self.assertNotIn(self.linux_token,json.dumps(state));self.assertNotIn("ADOld!123",json.dumps(state))
        self.assertEqual(self.client.post('/api/control',json={"action":"pause"}).status_code,403)
        self.client.headers['X-Godswork-CSRF']=state['csrf']
        self.assertEqual(self.client.post('/api/control',json={"action":"pause"}).status_code,200)
        self.assertEqual(self.client.post('/api/credential',json={"id":"ad-admin"}).json()['password'],"ADOld!123")
        self.assertEqual(self.client.post('/api/logout',json={}).status_code,200)
        self.assertEqual(self.client.get('/api/state').status_code,403)

    def test_wrong_vault_key_backup_and_inventory_validation(self):
        with self.assertRaises(InvalidToken): Store(self.path / "state.sqlite",Fernet.generate_key())
        backup=self.path/'backup.sqlite';self.store.backup(backup)
        self.assertEqual(Store(backup,self.key).snapshot()['credentials'][0]['id'],'linux-admin')
        self.assertEqual(backup.stat().st_mode & 0o777,0o600)
        bad=json.loads(json.dumps(self.inventory));bad['services'][0]['depends_on']=['linux-login']
        with self.assertRaises(ValueError):self.store.inventory(bad)
        for host in ('-oProxyCommand=anything','evil;touch /tmp/x','user@host'):
            with self.assertRaises(ValueError): Target(id='x',worker='w',host=host,transport='ssh',credential='c',known_hosts='known')

    def test_tools_rotation_flow_and_timeout_journaling(self):
        task=self.task(['ad','linux']);self.store.claim('ad-student');self.store.claim('linux-student')
        current={'ad':'ADOld!123','linux':'LinuxOld!123'}
        def executor(target, credential, command, runtime, timeout):
            if 'Set-ADAccountPassword' in command:
                self.assertEqual(credential['password'],current['ad'])
                pending=self.store.credential('ad-student',task['id'],'ad-admin','ad',True)['password']
                current['ad']=pending
            elif credential['id']=='ad-admin': self.assertEqual(credential['password'],current['ad'])
            return {'exit_code':0,'stdout':'verified','stderr':''}
        def tools_for(worker, token):
            tools=Tools({'coordinator':'http://127.0.0.1:8443','insecure_local':True,'token':token},task['id'],self.path,executor)
            tools.coordinator.client.close()
            tools.coordinator.client=TestClient(self.app,headers={'Authorization':'Bearer '+token})
            self.addCleanup(tools.coordinator.client.close)
            return tools
        ad=tools_for('ad-student',self.ad_token);linux=tools_for('linux-student',self.linux_token)
        rotation=ad.call('rotation_begin',credential='ad-admin')
        ad.rotate_apply(rotation['id']);ad.verify(rotation['id'],'ad');linux.verify(rotation['id'],'linux')
        ad.call('rotation_step',rotation=rotation['id'],action='commit',target='ad')
        def timeout(*args):raise subprocess.TimeoutExpired('ssh',120)
        linux.executor=timeout
        with self.assertRaises(RuntimeError):linux.run('linux','reload')
        self.assertEqual(self.store.snapshot()['tasks'][0]['state'],'uncertain')

    def test_ssh_transport_failure_retains_operation_and_lock(self):
        task=self.task();self.store.claim('linux-student')
        tools=Tools({'coordinator':'http://127.0.0.1:8443','insecure_local':True,'token':self.linux_token},task['id'],self.path,
                    lambda *args:{'exit_code':255,'stdout':'','stderr':'Connection lost'})
        tools.coordinator.client.close()
        tools.coordinator.client=TestClient(self.app,headers={'Authorization':'Bearer '+self.linux_token})
        self.addCleanup(tools.coordinator.client.close)
        with self.assertRaises(RuntimeError):tools.run('linux','reload')
        snapshot=self.store.snapshot()
        self.assertEqual(snapshot['operations'][0]['state'],'uncertain');self.assertTrue(snapshot['locks'])

    def test_two_worker_loops_coordinate_and_complete(self):
        """Exercise the real worker loop and coordinator, replacing only inference and remote IO."""
        import shutil
        from godswork.opencode import ROOT, VERSION
        from godswork.worker import run_worker
        task=self.task(['ad','linux'])
        shutil.copytree(ROOT/'skills',self.path/'skills')
        (self.path/'.tools/data').mkdir(parents=True)
        (self.path/'.tools/data/anonymous-check.json').write_text(json.dumps({'model':'opencode/space-bunny-free','version':VERSION,'checked_at':time.time()}))
        for worker, token in (('linux-student',self.linux_token),('ad-student',self.ad_token)):
            file=self.path/(worker+'.json')
            file.write_text(json.dumps({'id':worker,'token':token,'coordinator':'http://127.0.0.1:8443','insecure_local':True}))
            file.chmod(0o600)
        store=self.store;app=self.app
        class LocalCoordinator:
            def __init__(self,config):
                self.id=config['id'];self.client=TestClient(app,headers={'Authorization':'Bearer '+config['token']})
            def call(self,endpoint,**body):
                if endpoint=='claim' and store.snapshot()['tasks'][0]['state']=='done':
                    raise KeyboardInterrupt()
                response=self.client.post('/api/worker/'+endpoint,json=body)
                response.raise_for_status();return response.json()
        class LocalEngine:
            def __init__(self,directory,model,command,environment):
                self.config=json.loads(Path(environment['GODSWORK_WORKER_CONFIG']).read_text())
                self.task=environment['GODSWORK_TASK']
            def session(self,title):return 'fake-session'
            def prompt(self,session,prompt):
                worker=self.config['id'];target='ad' if worker=='ad-student' else 'linux'
                op=store.operation_start(worker,self.task,target,'verified service check')
                store.operation_finish(worker,op,{'exit_code':0,'stdout':'healthy'})
                store.message(worker,self.task,'Dependency checks healthy')
                return 'Verified '+target
            def close(self):pass
            def abort(self,session):pass
        with patch('godswork.worker.require_ubuntu_vm',return_value='kvm'),patch('godswork.worker.ROOT',self.path),patch('godswork.worker.Coordinator',LocalCoordinator),patch('godswork.worker.OpenCode',LocalEngine):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(run_worker,self.path/(w+'.json'),'opencode/space-bunny-free') for w in ('linux-student','ad-student')]
                for future in futures:future.result(timeout=20)
        snapshot=store.snapshot()
        self.assertEqual(snapshot['tasks'][0]['state'],'done')
        self.assertFalse(snapshot['locks']);self.assertEqual(len(snapshot['messages']),2)

    def test_opencode_requires_ubuntu_vm_before_launch_or_state_creation(self):
        for code, kind in ((1,'none'),(0,'wsl'),(1,'docker'),(0,'')):
            with self.subTest(kind=kind),patch('godswork.opencode.subprocess.run',return_value=subprocess.CompletedProcess([],code,kind,'')),patch('godswork.opencode.subprocess.Popen') as launch:
                with self.assertRaises(ValueError):OpenCode(self.path/'engine','opencode/space-bunny-free',[])
                launch.assert_not_called();self.assertFalse((self.path/'engine').exists())
        for kind in ('kvm','oracle','vmware','microsoft'):
            with patch('godswork.opencode.subprocess.run',return_value=subprocess.CompletedProcess([],0,kind+'\n','')),patch('godswork.opencode.platform.freedesktop_os_release',return_value={'ID':'ubuntu'}):
                self.assertEqual(require_ubuntu_vm(),kind)
        for error in (FileNotFoundError(),subprocess.TimeoutExpired('systemd-detect-virt',5)):
            with patch('godswork.opencode.subprocess.run',side_effect=error),self.assertRaises(ValueError):require_ubuntu_vm()
        with patch('godswork.opencode.subprocess.run',return_value=subprocess.CompletedProcess([],0,'microsoft','')),patch('godswork.opencode.platform.release',return_value='6.6.87-microsoft-standard-WSL2'),self.assertRaises(ValueError):require_ubuntu_vm()
        for distribution in ('debian','fedora','linuxmint','omarchy',None):
            with self.subTest(distribution=distribution),patch('godswork.opencode.subprocess.run',return_value=subprocess.CompletedProcess([],0,'kvm','')),patch('godswork.opencode.platform.freedesktop_os_release',return_value={'ID':distribution}),patch('godswork.opencode.subprocess.Popen') as launch:
                with self.assertRaises(ValueError):OpenCode(self.path/'engine','opencode/space-bunny-free',[])
                launch.assert_not_called();self.assertFalse((self.path/'engine').exists())
        with patch('godswork.opencode.subprocess.run',return_value=subprocess.CompletedProcess([],0,'kvm','')),patch('godswork.opencode.platform.freedesktop_os_release',side_effect=OSError()),self.assertRaises(ValueError):require_ubuntu_vm()

    def test_worker_and_preflight_reject_host_before_contacting_coordinator(self):
        from godswork.worker import preflight,run_worker
        with patch('godswork.worker.require_ubuntu_vm',side_effect=ValueError('Ubuntu VM required')),patch('godswork.worker.Coordinator') as coordinator:
            with self.assertRaises(ValueError):preflight(self.path/'absent.json')
            with self.assertRaises(ValueError):run_worker(self.path/'absent.json','opencode/space-bunny-free')
            coordinator.assert_not_called()


if __name__ == '__main__':
    unittest.main()
