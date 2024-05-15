import { CURRENT_USER_PATH, RULES_URL } from 'ui/config';

const ENDPOINT = {
  // Retrieving endpoints
  CURRENT_USER: {
    name: 'Fetching user data',
    url: CURRENT_USER_PATH,
  },
  SCIRIUS_CONTEXT: {
    name: 'Fetching scirius context',
    url: '/rest/rules/scirius_context',
  },
  SYSTEM_SETTINGS: {
    name: 'Fetching system settings data',
    url: `${RULES_URL}/system_settings/`,
  },
  SOURCES: {
    name: 'Fetching sources data',
    url: `/rest/rules/source/`,
  },
  ALL_PERIOD: {
    name: 'Fetching all period data',
    url: `${RULES_URL}/es/alerts_timerange/:tenant:eventTypes`,
  },
  RULE_SETS: {
    name: 'Fetching rule sets',
    url: `${RULES_URL}/ruleset/`,
  },
  HUNT_FILTER: {
    name: 'Fetching hunt filter',
    url: `${RULES_URL}/hunt-filter/`,
  },
  SUPPORTED_ACTIONS: {
    name: 'Fetching supported actions',
    url: `${RULES_URL}/processing-filter/test_actions/`,
  },
  HISTORY_FILTERS: {
    name: 'Fetching history filters',
    url: `${RULES_URL}/history/get_action_type_list/`,
  },
  FILTER_SET_SAVE: {
    name: 'Saving filter set',
    url: '/rest/rules/hunt_filter_sets/',
  },
  FILTER_SET_DELETE: {
    name: 'Deleting filter set',
    url: `/rest/rules/hunt_filter_sets/$id`,
  },
  SESSION_ACTIVITY: {
    name: 'Set session activity idle time',
    url: `/rest/accounts/sciriususer/session_activity/`,
  },
  FILTER_SETS: {
    name: 'Fetching filter sets',
    url: `/rest/rules/hunt_filter_sets`,
  },
  UPDATE_PUSH_RULESET: {
    name: 'Update / Push ruleset',
    url: process.env.REACT_APP_HAS_TAG === '1' ? '/rest/appliances/probe/update_push_all/' : '/rest/suricata/update_push_all/',
  },
  DASHBOARD_PANEL: {
    name: 'Fetch dashboard panel',
    url: '/rest/rules/es/fields_stats/:datesEs:tenant:eventTypes:qFilter',
  },
  DASHBOARD_PANEL_NO_FILTER: {
    name: 'Fetch dashboard panel',
    url: '/rest/rules/es/fields_stats/:datesEs:tenant:eventTypes',
  },
  FIELD_STATS: {
    name: 'Fetch Elasticsearch field stats',
    url: '/rest/rules/es/field_stats/:datesEs:tenant:eventTypes',
  },
  TIMELINE: {
    name: 'Fetch Elasticsearch timeline',
    url: '/rest/rules/es/timeline/?hosts=*:datesEs:tenant:eventTypes',
  },
  ALERTS_COUNT: {
    name: 'Fetch Elasticsearch alerts count',
    url: '/rest/rules/es/alerts_count/?prev=1&hosts=*:datesEs:tenant:eventTypes',
  },
  ALERTS_TAIL: {
    name: 'Fetch Elasticsearch alerts tail',
    url: '/rest/rules/es/alerts_tail/:qFilter:datesEs:tenant:eventTypes',
  },
  ALERTS_TAIL_WITHOUT_QFILTER: {
    name: 'Fetch Elasticsearch alerts tail',
    url: '/rest/rules/es/alerts_tail/:datesEs:tenant:eventTypes',
  },
  SIGNATURES: {
    name: 'Fetching signature',
    url: `/rest/rules/rule/:datesEs:filters:qFilter:eventTypes:withAlerts:tenant`,
  },
  SIGNATURE: {
    name: 'Fetching signature',
    url: `/rest/rules/rule/$sid`,
  },
  ELASTIC_SEARCH: {
    name: 'Fetching elasticsearch data',
    url: '/rest/rules/es/search/:datesEs:tenant',
  },
};

export default ENDPOINT;
