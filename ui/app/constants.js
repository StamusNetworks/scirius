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
};

export const huntTabs = {
  DASHBOARDS: 'Dashboard',
  ALERTS: 'Alerts',
  SIGNATURES: 'Signatures',
  POLICIES: 'Policy',
};

export const huntUrls = {
  DASHBOARDS: 'hunting/dashboards',
  ALERTS: 'hunting/alerts',
  SIGNATURES: 'hunting/signatures',
  POLICIES: 'hunting/policies',
};

export const APP_NAME_SHORT = 'Scirius CE';

/* GLOBAL CONSTANTS */

const DATE_TIME_FORMAT = 'YYYY-MM-DD HH:mm:ss';
const DATE_FORMAT = 'YYYY-MM-DD';

export default {
  DATE_TIME_FORMAT,
  DATE_FORMAT,
};
