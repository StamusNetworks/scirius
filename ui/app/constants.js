/*
Copyright(C) 2018-2022 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/

export const sections = {
  GLOBAL: 'ids_filters',
  HISTORY: 'history_filters',
  ALERT: 'alert_tag',
  USER: 'user',
};

export const PAGE_STATE = {
  rules_list: 'RULES_LIST',
  alerts_list: 'ALERTS_LIST',
  dashboards: 'DASHBOARDS',
  history: 'HISTORY',
  filters_list: 'FILTERS',
  setup: 'SETUP',
  inventory: 'INVENTORY',
  host_insight: 'HOST_INSIGHT',
};

export const huntTabs = {
  [PAGE_STATE.dashboards]: 'Dashboard',
  [PAGE_STATE.alerts_list]: 'Events',
  [PAGE_STATE.rules_list]: 'Signatures',
  [PAGE_STATE.filters_list]: 'Policy',
  [PAGE_STATE.inventory]: 'Inventory',
  [PAGE_STATE.host_insight]: 'Host Insight',
};

export const huntUrls = {
  [PAGE_STATE.dashboards]: 'hunting/dashboards',
  [PAGE_STATE.alerts_list]: 'hunting/events',
  [PAGE_STATE.rules_list]: 'hunting/signatures',
  [PAGE_STATE.filters_list]: 'hunting/policies',
  [PAGE_STATE.inventory]: 'analytics/inventory',
  [PAGE_STATE.host_insight]: 'hunting/hosts/',
};

export const APP_NAME_SHORT = 'Scirius CE';

/* GLOBAL CONSTANTS */

const DATE_TIME_FORMAT = 'YYYY-MM-DD HH:mm:ss';
const DATE_FORMAT = 'YYYY-MM-DD';

export default {
  DATE_TIME_FORMAT,
  DATE_FORMAT,
};
