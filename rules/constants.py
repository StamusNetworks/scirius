ES_NO_KEYWORD_FIELDS = (
    "src_port",
    "dest_port",
    "alert.signature_id",
    "alert.severity",
    "http.length",
    "http.status",
    "vlan",
    "geoip.provider.autonomous_system_number",
    "tunnel.depth",
    "flow.dest_port",
    "flow.src_port",
    "stamus.incidents_id",
    "stamus.asset_info.incident_id",
    "stamus.offender_info.incident_id",
)

USER_ACTIONS = {
    # Login/Logout
    "create_user": {
        "description": "{user} has created new user {new_user}",
        "title": "Create User",
        "perm": "rules.configuration_auth",
    },
    "edit_user": {
        "description": "{user} has edited user {other_user}",
        "title": "Edit User",
        "perm": "rules.configuration_auth",
    },
    "edit_user_token": {
        "description": "{user} has edited {other_user} token",
        "title": "Edit User Token",
        "perm": "rules.configuration_auth",
    },
    "edit_user_password": {
        "description": "{user} has edited {other_user} password",
        "title": "Edit User Password",
        "perm": "rules.configuration_auth",
    },
    "delete_user": {
        "description": "{user} has deleted user {old_user}",
        "title": "Delete User",
        "perm": "rules.configuration_auth",
    },
    "create_group": {
        "description": "{user} has created new role {new_group}",
        "title": "Create Role",
        "perm": "rules.configuration_auth",
    },
    "edit_group": {
        "description": "{user} has edited role {group}",
        "title": "Edit Role",
        "perm": "rules.configuration_auth",
    },
    "delete_group": {
        "description": "{user} has deleted role {group}",
        "title": "Delete Role",
        "perm": "rules.configuration_auth",
    },
    "login": {"description": "Logged in as {user}", "title": "Login", "perm": "rules.configuration_auth"},
    "logout": {"description": "{user} has logged out", "title": "Logout", "perm": "rules.configuration_auth"},
    # Sources:
    "create_source": {
        "description": "{user} has created source {source}",
        "title": "Create Source",
        "perm": "rules.source_view",
    },
    "update_source": {
        "description": "{user} has updated source {source}",
        "title": "Update Source",
        "perm": "rules.source_view",
    },
    "edit_source": {
        "description": "{user} has edited source {source}",
        "title": "Edit Source",
        "perm": "rules.source_view",
    },
    "upload_source": {
        "description": "{user} has uploaded source {source}",
        "title": "Upload Source",
        "perm": "rules.source_view",
    },
    "enable_source": {
        "description": "{user} has enabled source {source} in ruleset {ruleset}",
        "title": "Enable Source",
        "perm": "rules.source_view",
    },
    "disable_source": {
        "description": "{user} has disabled source {source} in ruleset {ruleset}",
        "title": "Disable Source",
        "perm": "rules.source_view",
    },
    "delete_source": {
        "description": "{user} has deleted source {source}",
        "title": "Delete Source",
        "perm": "rules.source_view",
    },
    # Rulesets:
    "create_ruleset": {
        "description": "{user} has created ruleset {ruleset}",
        "title": "Create Ruleset",
        "perm": "rules.source_view",
    },
    "transform_ruleset": {
        "description": "{user} has transformed ruleset {ruleset} to {transformation}",
        "title": "Transform Ruleset",
        "perm": "rules.source_view",
    },
    "edit_ruleset": {
        "description": "{user} has edited ruleset {ruleset}",
        "title": "Edit Ruleset",
        "perm": "rules.source_view",
    },
    "copy_ruleset": {
        "description": "{user} has copied ruleset {ruleset}",
        "title": "Copy Ruleset",
        "perm": "rules.source_view",
    },
    "delete_ruleset": {
        "description": "{user} has deleted ruleset {ruleset}",
        "title": "Delete Ruleset",
        "perm": "rules.source_view",
    },
    # Categories:
    "enable_category": {
        "description": "{user} has enabled category {category} in ruleset {ruleset}",
        "title": "Enable Category",
        "perm": "rules.ruleset_policy_view",
    },
    "transform_category": {
        "description": "{user} has transformed category {category} to {transformation} in ruleset {ruleset}",
        "title": "Transform Category",
        "perm": "rules.ruleset_policy_view",
    },
    "disable_category": {
        "description": "{user} has disabled category {category} in ruleset {ruleset}",
        "title": "Disable Category",
        "perm": "rules.ruleset_policy_view",
    },
    # Rules:
    "enable_rule": {
        "description": "{user} has enabled rule {rule} in ruleset {ruleset}",
        "title": "Enable Rule",
        "perm": "rules.ruleset_policy_view",
    },
    "comment_rule": {
        "description": "{user} has commented rule {rule}",
        "title": "Comment Rule",
        "perm": "rules.ruleset_policy_view",
    },
    "transform_rule": {
        "description": "{user} has transformed rule {rule} to {transformation} in ruleset {ruleset}",
        "title": "Transform Rule",
        "perm": "rules.ruleset_policy_view",
    },
    "suppress_rule": {
        "description": "{user} has suppressed rule {rule} in ruleset {ruleset}",
        "title": "Suppress Rule",
        "perm": "rules.ruleset_policy_view",
    },
    "disable_rule": {
        "description": "{user} has disabled rule {rule} in ruleset {ruleset}",
        "title": "Disable Rule",
        "perm": "rules.ruleset_policy_view",
    },
    "delete_suppress_rule": {
        "description": "{user} has deleted suppressed rule {rule} in ruleset {ruleset}",
        "title": "Delete Suppress Rule",
        "perm": "rules.ruleset_policy_view",
    },
    # Toggle availability
    "toggle_availability": {
        "description": "{user} has modified rule availability {rule}",
        "title": "Toggle Availability",
        "perm": "rules.ruleset_policy_view",
    },
    # Thresholds:
    "create_threshold": {
        "description": "{user} has created threshold on rule {rule} in ruleset {ruleset}",
        "title": "Create Threshold",
        "perm": "rules.ruleset_policy_view",
    },
    "edit_threshold": {
        "description": "{user} has edited threshold {threshold} on rule {rule} in ruleset {ruleset}",
        "title": "Edit Threshold",
        "perm": "rules.ruleset_policy_view",
    },
    "delete_threshold": {
        "description": "{user} has deleted threshold {threshold} on rule {rule} in ruleset {ruleset}",
        "title": "Delete Threshold",
        "perm": "rules.ruleset_policy_view",
    },
    # Used only in REST API
    "delete_transform_ruleset": {
        "description": "{user} has deleted transformation {transformation} on ruleset {ruleset}",
        "title": "Deleted Ruleset Transformation",
        "perm": "rules.ruleset_policy_view",
    },
    "delete_transform_rule": {
        "description": "{user} has deleted transformation {transformation} on rule {rule} in ruleset {ruleset}",
        "title": "Delete Rule Transformation",
        "perm": "rules.ruleset_policy_view",
    },
    "delete_transform_category": {
        "description": "{user} has deleted transformation {transformation} on category {category} in ruleset {ruleset}",
        "title": "Delete Category Transformation",
        "perm": "rules.ruleset_policy_view",
    },
    # End REST API
    # Suricata
    "edit_suricata": {
        "description": "{user} has edited suricata",
        "title": "Edit Suricata",
        "perm": "rules.configuration_view",
    },
    "create_suricata": {
        "description": "{user} has created suricata",
        "title": "Create Suricata",
        "perm": "rules.configuration_view",
    },
    "update_push_all": {
        "description": "{user} has pushed ruleset {ruleset}",
        "title": "Update/Push ruleset",
        "perm": "rules.ruleset_update_push",
    },
    # Settings
    "system_settings": {
        "description": "{user} has edited system settings",
        "title": "Edit System Settings",
        "perm": "rules.configuration_view",
    },
    "delete_alerts": {
        "description": "{user} has deleted alerts from rule {rule}",
        "title": "Delete Alerts",
        "perm": "rules.events_view",
    },
    # Rule processing filter
    "create_rule_filter": {
        "description": "{user} has created rule filter {rule_filter} in ruleset {ruleset}",
        "title": "Create rule filter",
        "perm": "rules.events_view",
    },
    "import_rule_filter": {
        "description": "{user} has imported rule filter(s) in ruleset {ruleset}",
        "title": "Import rule filter",
        "perm": "rules.events_view",
    },
    "edit_rule_filter": {
        "description": "{user} has edited rule filter {rule_filter} in ruleset {ruleset}",
        "title": "Edit rule filter",
        "perm": "rules.events_view",
    },
    "delete_rule_filter": {
        "description": "{user} has deleted rule filter {rule_filter} in ruleset {ruleset}",
        "title": "Delete rule filter",
        "perm": "rules.events_view",
    },
}
