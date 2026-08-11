from .admin import register_admin_routes
from .applications import register_application_routes
from .auth import register_auth_routes
from .cloud import register_cloud_routes
from .status import register_status_routes
from .update import register_update_routes
from .vpn import register_vpn_routes

__all__ = [
    "register_admin_routes",
    "register_application_routes",
    "register_auth_routes",
    "register_cloud_routes",
    "register_status_routes",
    "register_update_routes",
    "register_vpn_routes",
]
