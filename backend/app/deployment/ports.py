"""Port ownership policy shared by deployment lifecycle operations."""


def stopped_reservation_status(*, release_ports: bool) -> str:
    """Return the reservation state after stopping a runtime."""
    return "released" if release_ports else "reserved"


def stopped_port_message(*, release_ports: bool) -> str:
    return "端口已释放" if release_ports else "原端口已为该项目保留"
