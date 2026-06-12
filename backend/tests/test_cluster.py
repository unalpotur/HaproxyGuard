from app.cluster import ClusterRegistry, config_hash
from app.cluster.models import HeartbeatInput

CFG = "defaults\n    mode http\n    timeout connect 5s\n    timeout client 30s\n    timeout server 30s\n"
CFG2 = CFG + "frontend f\n    bind *:80\n    default_backend b\nbackend b\n    server s 1.1.1.1:80 check\n"


def test_enroll_returns_token_once():
    reg = ClusterRegistry()
    resp = reg.enroll("edge-1", "10.0.0.1", {"role": "edge"})
    assert resp.token  # plaintext token returned
    assert resp.node.status == "pending"  # no heartbeat yet
    # the registry stores only a hash, never the plaintext
    assert reg._nodes[resp.node.id].token_hash != resp.token


def test_token_authentication():
    reg = ClusterRegistry()
    resp = reg.enroll("n", "10.0.0.1", {})
    assert reg.authenticate(resp.node.id, resp.token) is True
    assert reg.authenticate(resp.node.id, "wrong") is False
    assert reg.authenticate("node_missing", resp.token) is False


def test_heartbeat_marks_online_and_updates_fields():
    reg = ClusterRegistry()
    nid = reg.enroll("n", "10.0.0.1", {}).node.id
    reg.heartbeat(nid, HeartbeatInput(agent_version="1.0", haproxy_version="2.8", config_hash="abc"))
    node = reg.get(nid)
    assert node.status == "online"
    assert node.haproxy_version == "2.8"
    assert node.config_hash == "abc"


def test_offline_after_threshold():
    reg = ClusterRegistry(offline_after=-1)  # everything immediately offline
    nid = reg.enroll("n", "10.0.0.1", {}).node.id
    reg.heartbeat(nid, HeartbeatInput())
    assert reg.get(nid).status == "offline"


def test_deploy_and_agent_convergence():
    reg = ClusterRegistry()
    nid = reg.enroll("n", "10.0.0.1", {}).node.id
    result = reg.deploy(CFG, node_ids=[nid], selector=None, validate_config=False)
    assert len(result.deployments) == 1
    dep = result.deployments[0]
    assert dep.status == "pending"
    assert reg.get(nid).pending_version == 1

    # agent pulls the desired config on heartbeat (it is behind)
    hb = reg.heartbeat(nid, HeartbeatInput(config_version=None))
    assert hb.desired_version == 1
    assert hb.desired_config == CFG

    # agent applies and reports the new version → deployment converges
    reg.heartbeat(nid, HeartbeatInput(config_version=1, config_hash=config_hash(CFG)))
    assert reg.deployments(nid)[0].status == "applied"
    assert reg.get(nid).applied_version == 1
    # now up to date — no config pushed back
    hb2 = reg.heartbeat(nid, HeartbeatInput(config_version=1))
    assert hb2.desired_config is None


def test_deploy_by_selector():
    reg = ClusterRegistry()
    edge = reg.enroll("e", "10.0.0.1", {"role": "edge"}).node.id
    reg.enroll("i", "10.0.0.2", {"role": "internal"})
    result = reg.deploy(CFG, node_ids=None, selector={"role": "edge"}, validate_config=False)
    assert [d.node_id for d in result.deployments] == [edge]


def test_rollback_restores_previous_config():
    reg = ClusterRegistry()
    nid = reg.enroll("n", "10.0.0.1", {}).node.id
    reg.deploy(CFG, [nid], None, validate_config=False)
    reg.deploy(CFG2, [nid], None, validate_config=False)
    assert reg._nodes[nid].desired_config == CFG2

    dep = reg.rollback(nid)
    assert dep is not None
    assert reg._nodes[nid].desired_config == CFG  # back to the first config
    # agent gets the rolled-back config on next heartbeat
    hb = reg.heartbeat(nid, HeartbeatInput())
    assert hb.desired_config == CFG


def test_rollback_without_history():
    reg = ClusterRegistry()
    nid = reg.enroll("n", "10.0.0.1", {}).node.id
    assert reg.rollback(nid) is None  # nothing deployed yet


def test_overview_counts_and_drift():
    reg = ClusterRegistry()
    a = reg.enroll("a", "10.0.0.1", {}).node.id
    b = reg.enroll("b", "10.0.0.2", {}).node.id
    reg.heartbeat(a, HeartbeatInput(haproxy_version="2.8", config_hash="h1"))
    reg.heartbeat(b, HeartbeatInput(haproxy_version="3.0", config_hash="h2"))
    ov = reg.overview()
    assert ov.total == 2
    assert ov.online == 2
    assert ov.distinct_config_hashes == 2  # configuration drift
    assert ov.haproxy_versions == {"2.8": 1, "3.0": 1}
