import { API_URL, RULES_URL, CURRENT_USER_PATH } from 'ui/config';

const ENDPOINT = {
  // Retrieving endpoints
  CURRENT_USER: {
    name: 'Fetching user data',
    url: CURRENT_USER_PATH,
  },
  GLOBAL_SETTINGS: {
    name: 'Fetching global settings data',
    url: `${API_URL}/global_settings`,
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
    url: `${RULES_URL}/es/alerts_timerange/:filters`,
  },
}

export default ENDPOINT;
