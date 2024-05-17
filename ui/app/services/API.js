import ENDPOINT from 'ui/config/endpoints';
import { api } from 'ui/mobx/api';

const API = {
  // POST
  setSessionActivity: async (params, options) => api.post(ENDPOINT.SESSION_ACTIVITY.url, params, options),
  saveFilterSet: async (params, options) => api.post(ENDPOINT.FILTER_SET_SAVE.url, params, options),
  updatePushRuleset: async () => api.post(ENDPOINT.UPDATE_PUSH_RULESET.url),
  // GET
  fetchUser: async () => api.get(ENDPOINT.CURRENT_USER.url),
  fetchContext: async () => api.get(ENDPOINT.SCIRIUS_CONTEXT.url),
  fetchSystemSettings: async () => api.get(ENDPOINT.SYSTEM_SETTINGS.url),
  fetchSources: async params => api.get(ENDPOINT.SOURCES.url, params),
  fetchAllPeriod: async params => api.get(ENDPOINT.ALL_PERIOD.url, params),
  fetchRuleSets: async () => api.get(ENDPOINT.RULE_SETS.url),
  fetchSupportedActions: async (params, options) => api.post(ENDPOINT.SUPPORTED_ACTIONS.url, params, options),
  fetchHistoryFilters: async () => api.get(ENDPOINT.HISTORY_FILTERS.url),
  fetchFilterSets: async () => api.get(ENDPOINT.FILTER_SETS.url),
  fetchDashboardPanel: async (params, options) => api.get(ENDPOINT.DASHBOARD_PANEL.url, params, options),
  fetchFieldStats: async (params, options) => api.get(ENDPOINT.FIELD_STATS.url, params, options),
  fetchTimeline: async (params, options) => api.get(ENDPOINT.TIMELINE.url, params, options),
  fetchAlertsCount: async (params, options) => api.get(ENDPOINT.ALERTS_COUNT.url, params, options),
  fetchAlertsTail: async (params, options) => api.get(ENDPOINT.ALERTS_TAIL.url, params, options),
  fetchPoliciesData: async (params, options) => api.get(ENDPOINT.POLICIES_DATA.url, params, options),
  fetchProcessingFilters: async (params, options) => api.get(ENDPOINT.PROCESSING.url, params, options),
  // DELETE
  deleteFilterSet: async (params, options) => api.delete(ENDPOINT.FILTER_SET_DELETE.url, params, options),
};

export default API;
