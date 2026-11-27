from app.deployment.ports import stopped_port_message, stopped_reservation_status


def test_user_pause_retains_project_port():
    assert stopped_reservation_status(release_ports=False) == "reserved"
    assert "保留" in stopped_port_message(release_ports=False)


def test_retired_version_returns_port_to_pool():
    assert stopped_reservation_status(release_ports=True) == "released"
    assert "释放" in stopped_port_message(release_ports=True)
