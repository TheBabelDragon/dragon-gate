"""Route selection and failover."""

from dragon_gate.network.routes import Route, RouteTable


def test_select_lowest_metric():
    table = RouteTable()
    table.upsert(Route(destination="svc", next_hop="a", metric=50))
    table.upsert(Route(destination="svc", next_hop="b", metric=10))
    r = table.select("svc")
    assert r and r.next_hop == "b"


def test_failover():
    table = RouteTable()
    table.upsert(Route(destination="svc", next_hop="a", metric=10))
    table.upsert(Route(destination="svc", next_hop="b", metric=20))
    first = table.select("svc")
    assert first and first.next_hop == "a"
    second = table.failover("svc")
    assert second and second.next_hop == "b"


def test_gateway_unavailable_selection():
    from dragon_gate.network.gateways import Gateway, GatewayRegistry, GatewayState

    reg = GatewayRegistry()
    reg.register(Gateway(gateway_id="g1", endpoint="http://g1", authorized=True))
    reg.set_state("g1", GatewayState.UNAVAILABLE)
    assert reg.select_authorized() is None
