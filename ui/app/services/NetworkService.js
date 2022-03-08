import ENDPOINT from 'ui/config/endpoints';
import Api from 'ui/helpers/Api';

const NetworkService = {
  // GET
  fetchUser: async () => Api.get(ENDPOINT.CURRENT_USER),
  fetchGlobalSettings: async () => Api.get(ENDPOINT.GLOBAL_SETTINGS),
  fetchSystemSettings: async () => Api.get(ENDPOINT.SYSTEM_SETTINGS),
  fetchSources: async () => Api.get(ENDPOINT.SOURCES),
  fetchAllPeriod: async (params) => Api.get(ENDPOINT.ALL_PERIOD, params),
}

export default NetworkService;
