from django.conf import settings
from django.urls import re_path
from rest_framework.routers import DefaultRouter

from rules.api.category import CategoryViewSet
from rules.api.es import (
    ESAlertsCountViewSet,
    ESAlertsTailViewSet,
    ESCheckVersionViewSet,
    ESDeleteLogsViewSet,
    ESEventsFromFlowIDViewSet,
    ESEventsTailViewSet,
    ESEventsTimelineViewSet,
    ESFieldsStatsViewSet,
    ESFieldStatsViewSet,
    ESFieldUniqViewSet,
    ESFilterIPViewSet,
    ESFlowTimelineViewSet,
    ESGenericSearchViewSet,
    ESGraphAggViewSet,
    ESHealthViewSet,
    ESIPFlowTimelineViewSet,
    ESIPPairAlertsViewSet,
    ESIPPairNetworkAlertsViewSet,
    ESLatestStatsViewSet,
    ESLogstashEveViewSet,
    ESMappingViewSet,
    ESPostStatsViewSet,
    ESRulesPerCategoryViewSet,
    ESRulesViewSet,
    ESRuleViewSet,
    ESShardStatsViewSet,
    ESSigsListViewSet,
    ESStatsViewSet,
    ESSuriLogTailViewSet,
    ESTimelineViewSet,
    ESTimeRangeAllAlertsViewSet,
    ESTLSTailViewSet,
    ESTopRulesViewSet,
    ESUniqueFieldViewSet,
    HuntFilterAPIView,
)
from rules.api.filter_set import FilterSetViewSet
from rules.api.misc import DeepLinkViewSet, SciriusContextAPIView, SystemSettingsViewSet, UserActionViewSet
from rules.api.processing import RuleProcessingFilterViewSet
from rules.api.ruleset import RulesetViewSet
from rules.api.rule import (
    CategoryTransformationViewSet,
    RuleViewSet,
    RulesetTransformationViewSet,
    RuleTransformationViewSet,
)
from rules.api.source import ChangelogViewSet, PublicSourceViewSet, SourceViewSet


Probe = __import__(settings.RULESET_MIDDLEWARE)


def get_custom_urls():
    # Make MCP endpoints available
    from rules.mcp import McpController  # noqa: F401

    urls = []
    url_ = re_path(
        r"rules/system_settings/$",
        SystemSettingsViewSet.as_view(
            {
                "get": "retrieve",
                "put": "update",
                "patch": "partial_update",
            }
        ),
        name="systemsettings",
    )

    urls.append(url_)

    url_ = re_path(r"rules/hunt-filter/$", HuntFilterAPIView.as_view(), name="hunt_filter")
    urls.append(url_)

    urls.append(re_path(r"rules/es/mapping/$", ESMappingViewSet.as_view(), name="es_rules"))
    urls.append(re_path(r"rules/es/rules/$", ESRulesViewSet.as_view(), name="es_rules"))
    urls.append(re_path(r"rules/es/rule/$", ESRuleViewSet.as_view(), name="es_rule"))
    urls.append(re_path(r"rules/es/filter_ip/$", ESFilterIPViewSet.as_view(), name="es_filter_ip"))
    urls.append(re_path(r"rules/es/field_stats/$", ESFieldStatsViewSet.as_view(), name="es_field_stats"))
    urls.append(re_path(r"rules/es/fields_stats/$", ESFieldsStatsViewSet.as_view(), name="es_fields_stats"))
    urls.append(re_path(r"rules/es/poststats_summary/$", ESPostStatsViewSet.as_view(), name="es_poststats_summary"))
    urls.append(re_path(r"rules/es/sigs_list/$", ESSigsListViewSet.as_view(), name="es_sigs_list"))
    urls.append(re_path(r"rules/es/top_rules/$", ESTopRulesViewSet.as_view(), name="es_top_rules"))
    urls.append(re_path(r"rules/es/timeline/$", ESTimelineViewSet.as_view(), name="es_timeline"))
    urls.append(re_path(r"rules/es/logstash_eve/$", ESLogstashEveViewSet.as_view(), name="es_logstash_eve"))
    urls.append(re_path(r"rules/es/health/$", ESHealthViewSet.as_view(), name="es_health"))
    urls.append(re_path(r"rules/es/stats/$", ESStatsViewSet.as_view(), name="es_stats"))
    urls.append(re_path(r"rules/es/shard_stats/$", ESShardStatsViewSet.as_view(), name="es_shard_stats"))
    urls.append(re_path(r"rules/es/check_version/$", ESCheckVersionViewSet.as_view(), name="es_check_version"))
    urls.append(
        re_path(r"rules/es/rules_per_category/$", ESRulesPerCategoryViewSet.as_view(), name="es_rules_per_category")
    )
    urls.append(re_path(r"rules/es/alerts_count/$", ESAlertsCountViewSet.as_view(), name="es_alerts_count"))
    urls.append(
        re_path(r"rules/es/alerts_timerange/$", ESTimeRangeAllAlertsViewSet.as_view(), name="es_alerts_timerange")
    )
    urls.append(re_path(r"rules/es/latest_stats/$", ESLatestStatsViewSet.as_view(), name="es_latest_stats"))
    urls.append(re_path(r"rules/es/ip_pair_alerts/$", ESIPPairAlertsViewSet.as_view(), name="es_ip_pair_alerts"))
    urls.append(
        re_path(
            r"rules/es/ip_pair_network_alerts/$",
            ESIPPairNetworkAlertsViewSet.as_view(),
            name="es_ip_pair_network_alerts",
        )
    )
    urls.append(re_path(r"rules/es/alerts_tail/$", ESAlertsTailViewSet.as_view(), name="es_alerts_tail"))
    urls.append(re_path(r"rules/es/events_tail/$", ESEventsTailViewSet.as_view(), name="es_events_tail"))
    urls.append(re_path(r"rules/es/tls_tail/$", ESTLSTailViewSet.as_view(), name="es_tls_tail"))
    urls.append(re_path(r"rules/es/events_timeline/$", ESEventsTimelineViewSet.as_view(), name="es_events_timeline"))
    urls.append(re_path(r"rules/es/flow_timeline/$", ESFlowTimelineViewSet.as_view(), name="es_flow_timeline"))
    urls.append(re_path(r"rules/es/ip_flow_timeline/$", ESIPFlowTimelineViewSet.as_view(), name="es_ip_flow_timeline"))
    urls.append(
        re_path(r"rules/es/events_from_flow_id/$", ESEventsFromFlowIDViewSet.as_view(), name="es_events_from_flow_id")
    )
    urls.append(re_path(r"rules/es/suri_log_tail/$", ESSuriLogTailViewSet.as_view(), name="es_suri_log_tail"))
    urls.append(re_path(r"rules/es/delete_logs/$", ESDeleteLogsViewSet.as_view(), name="es_delete_logs"))
    urls.append(re_path(r"rules/scirius_context/$", SciriusContextAPIView.as_view(), name="scirius_context"))
    urls.append(re_path(r"rules/es/unique_fields/$", ESUniqueFieldViewSet.as_view(), name="es_unique_fields"))
    urls.append(re_path(r"rules/es/graph_agg/$", ESGraphAggViewSet.as_view(), name="es_graph_agg"))
    urls.append(re_path(r"rules/es/unique_values/$", ESFieldUniqViewSet.as_view(), name="es_unique_values"))
    urls.append(re_path(r"rules/es/search/$", ESGenericSearchViewSet.as_view(), name="es_search"))

    return urls


router = DefaultRouter()
router.register("rules/ruleset", RulesetViewSet)
router.register("rules/category", CategoryViewSet)
router.register("rules/rule", RuleViewSet)
router.register("rules/source", SourceViewSet, basename="source")
router.register("rules/public_source", PublicSourceViewSet, basename="publicsource")
router.register("rules/transformation/ruleset", RulesetTransformationViewSet)
router.register("rules/transformation/category", CategoryTransformationViewSet)
router.register("rules/transformation/rule", RuleTransformationViewSet)
router.register("rules/history", UserActionViewSet)
router.register("rules/changelog/source", ChangelogViewSet)
router.register("rules/system_settings", SystemSettingsViewSet)
router.register("rules/processing-filter", RuleProcessingFilterViewSet)
router.register("rules/hunt_filter_sets", FilterSetViewSet, basename="hunt_filter_sets")
router.register("rules/deeplink", DeepLinkViewSet)
