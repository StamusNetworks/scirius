import ENDPOINT from 'ui/config/endpoints';
import Api from 'ui/helpers/Api';

const NetworkService = {
  // POST
  setSessionActivity: async (params, options) => Api.post(ENDPOINT.SESSION_ACTIVITY, params, options),
  saveFilterSet: async (params, options) => Api.post(ENDPOINT.FILTER_SET_SAVE, params, options),
  updatePushRuleset: async () => Api.post(ENDPOINT.UPDATE_PUSH_RULESET),
  // GET
  fetchUser: async () => Api.get(ENDPOINT.CURRENT_USER),
  fetchContext: async () => Api.get(ENDPOINT.SCIRIUS_CONTEXT),
  fetchSystemSettings: async () => Api.get(ENDPOINT.SYSTEM_SETTINGS),
  fetchSources: async params => Api.get(ENDPOINT.SOURCES, params),
  fetchAllPeriod: async params => Api.get(ENDPOINT.ALL_PERIOD, params),
  fetchRuleSets: async () => Api.get(ENDPOINT.RULE_SETS),
  fetchHuntFilter: async () => Api.get(ENDPOINT.HUNT_FILTER),
  fetchSupportedActions: async (params, options) => Api.post(ENDPOINT.SUPPORTED_ACTIONS, params, options),
  fetchHistoryFilters: async () => Api.get(ENDPOINT.HISTORY_FILTERS),
};

export default NetworkService;
