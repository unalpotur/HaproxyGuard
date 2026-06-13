from app.cluster import ClusterRegistry, config_hash
from app.cluster.models import HeartbeatInput

CFG = "defaults\n    mode http\n    timeout connect 5s\n    timeout client 30s\n    timeout server 30s\n"
CFG2 = CFG + "frontend f\n    bind *:80\n    default_backend b\nbackend b\n    server s 1.1.1.1:80 check\n"


async def test_enroll_returns_token_once(db, session_factory):
    reg = ClusterRegistry(session_factory)
    resp = await reg.enroll("edge-1", "10.0.0.1", {"role": "edge"})
    assert resp.token  # plaintext token returned
    assert resp.node.status == "pending"  # no heartbeat yet
    # the registry stores only a hash, never the plaintext
    assert await reg.authenticate(resp.node.id, resp.token) is True


async def test_token_authentication(db, session_factory):
    reg = ClusterRegistry(session_factory)
    resp = await reg.enroll("n", "10.0.0.1", {})
    assert await reg.authenticate(resp.node.id, resp.token) is True
    assert await reg.authenticate(resp.node.id, "wrong") is False
    assert await reg.authenticate("node_missing", resp.token) is False


async def test_heartbeat_marks_online_and_updates_fields(db, session_factory):
    reg = ClusterRegistry(session_factory)
    resp = await reg.enroll("n", "10.0.0.1", {})
    nid = resp.node.id
    await reg.heartbeat(nid, HeartbeatInput(agent_version="1.0", haproxy_version="2.8", config_hash="abc"))
    node = await reg.get(nid)
    assert node.status == "online"
    assert node.haproxy_version == "2.8"
    assert node.config_hash == "abc"


async def test_offline_after_threshold(db, session_factory):
    reg = ClusterRegistry(session_factory, offline_after=-1)  # everything immediately offline
    resp = await reg.enroll("n", "10.0.0.1", {})
    nid = resp.node.id
    await reg.heartbeat(nid, HeartbeatInput())
    assert (await reg.get(nid)).status == "offline"


async def test_deploy_and_agent_convergence(db, session_factory):
    reg = ClusterRegistry(session_factory)
    resp = await reg.enroll("n", "10.0.0.1", {})
    nid = resp.node.id
    result = await reg.deploy(CFG, node_ids=[nid], selector=None, validate_config=False)
    assert len(result.deployments) == 1
    dep = result.deployments[0]
    assert dep.status == "pending"
    assert (await reg.get(nid)).pending_version == 1

    # agent pulls the desired config on heartbeat (it is behind)
    hb = await reg.heartbeat(nid, HeartbeatInput(config_version=None))
    assert hb.desired_version == 1
    assert hb.desired_config == CFG

    # agent applies and reports the new version → deployment converges
    await reg.heartbeat(nid, HeartbeatInput(config_version=1, config_hash=config_hash(CFG)))
    assert (await reg.deployments(nid))[0].status == "applied"
    assert (await reg.get(nid)).applied_version == 1
    # now up to date — no config pushed back
    hb2 = await reg.heartbeat(nid, HeartbeatInput(config_version=1))
    assert hb2.desired_config is None


async def test_deploy_by_selector(db, session_factory):
    reg = ClusterRegistry(session_factory)
    resp = await reg.enroll("e", "10.0.0.1", {"role": "edge"})
    edge = resp.node.id
    await reg.enroll("i", "10.0.0.2", {"role": "internal"})
    result = await reg.deploy(CFG, node_ids=None, selector={"role": "edge"}, validate_config=False)
    assert [d.node_id for d in result.deployments] == [edge]


async def test_rollback_restores_previous_config(db, session_factory):
    reg = ClusterRegistry(session_factory)
    resp = await reg.enroll("n", "10.0.0.1", {})
    nid = resp.node.id
    await reg.deploy(CFG, [nid], None, validate_config=False)
    await reg.deploy(CFG2, [nid], None, validate_config=False)

    dep = await reg.rollback(nid)
    assert dep is not None
    # agent gets the rolled-back config on next heartbeat
    hb = await reg.heartbeat(nid, HeartbeatInput())
    assert hb.desired_config == CFG


async def test_rollback_without_history(db, session_factory):
    reg = ClusterRegistry(session_factory)
    resp = await reg.enroll("n", "10.0.0.1", {})
    nid = resp.node.id
    assert await reg.rollback(nid) is None  # nothing deployed yet


async def test_overview_counts_and_drift(db, session_factory):
    reg = ClusterRegistry(session_factory)
    a = (await reg.enroll("a", "10.0.0.1", {})).node.id
    b = (await reg.enroll("b", "10.0.0.2", {})).node.id
    await reg.heartbeat(a, HeartbeatInput(haproxy_version="2.8", config_hash="h1"))
    await reg.heartbeat(b, HeartbeatInput(haproxy_version="3.0", config_hash="h2"))
    ov = await reg.overview()
    assert ov.total == 2
    assert ov.online == 2
    assert ov.distinct_config_hashes == 2  # configuration drift
    assert ov.haproxy_versions == {"2.8": 1, "3.0": 1}
