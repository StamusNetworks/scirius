/*
 * AppConstants
 * Each action has a corresponding type, which the reducer knows and picks up on.
 * To avoid weird typos between the reducer and the actions, we save them as
 * constants here. We prefix them with 'yourproject/YourComponent' so we avoid
 * reducers accidentally picking up actions they shouldn't.
 *
 * Follow this format:
 * export const YOUR_ACTION_CONSTANT = 'yourproject/YourContainer/YOUR_ACTION_CONSTANT';
 */

export const LOCATION_CHANGE = '@@router/LOCATION_CHANGE';
export const GET_FAMILIES_REQUEST = 'redlights/App/GET_FAMILIES_REQUEST';
export const GET_FAMILIES_SUCCESS = 'redlights/App/GET_FAMILIES_SUCCESS';
export const GET_FAMILIES_FAILURE = 'redlights/App/GET_FAMILIES_FAILURE';
export const GET_ACTIVE_FAMILIES_REQUEST = 'redlights/App/GET_ACTIVE_FAMILIES_REQUEST';
export const GET_ACTIVE_FAMILIES_SUCCESS = 'redlights/App/GET_ACTIVE_FAMILIES_SUCCESS';
export const GET_ACTIVE_FAMILIES_FAILURE = 'redlights/App/GET_ACTIVE_FAMILIES_FAILURE';
export const GET_USER_REQUEST = 'redlights/App/GET_USER_REQUEST';
export const GET_USER_SUCCESS = 'redlights/App/GET_USER_SUCCESS';
export const GET_USER_FAILURE = 'redlights/App/GET_USER_FAILURE';
export const GET_THREATS_REQUEST = 'redlights/App/GET_THREATS_REQUEST';
export const GET_THREATS_SUCCESS = 'redlights/App/GET_THREATS_SUCCESS';
export const GET_THREATS_FAILURE = 'redlights/App/GET_THREATS_FAILURE';
export const GET_ACTIVE_THREATS_REQUEST = 'redlights/App/GET_ACTIVE_THREATS_REQUEST';
export const GET_ACTIVE_THREATS_SUCCESS = 'redlights/App/GET_ACTIVE_THREATS_SUCCESS';
export const GET_ACTIVE_THREATS_FAILURE = 'redlights/App/GET_ACTIVE_THREATS_FAILURE';
export const GET_GLOBAL_SETTINGS_REQUEST = 'redlights/App/GET_GLOBAL_SETTINGS_REQUEST';
export const GET_GLOBAL_SETTINGS_SUCCESS = 'redlights/App/GET_GLOBAL_SETTINGS_SUCCESS';
export const GET_GLOBAL_SETTINGS_FAILURE = 'redlights/App/GET_GLOBAL_SETTINGS_FAILURE';
export const GET_TENANTS_REQUEST = 'redlights/App/GET_TENANTS_REQUEST';
export const GET_TENANTS_SUCCESS = 'redlights/App/GET_TENANTS_SUCCESS';
export const GET_TENANTS_FAILURE = 'redlights/App/GET_TENANTS_FAILURE';
export const DELETE_THREAT_REQUEST = 'redlights/App/DELETE_THREAT_REQUEST';
export const DELETE_THREAT_SUCCESS = 'redlights/App/DELETE_THREAT_SUCCESS';
export const DELETE_THREAT_FAILURE = 'redlights/App/DELETE_THREAT_FAILURE';
export const GET_SOURCE_REQUEST = 'redlights/App/GET_SOURCE_REQUEST';
export const GET_SOURCE_SUCCESS = 'redlights/App/GET_SOURCE_SUCCESS';
export const GET_SOURCE_FAILURE = 'redlights/App/GET_SOURCE_FAILURE';
export const SET_TIME_SPAN = 'redlights/App/SET_TIME_SPAN';
export const SET_DURATION = 'redlights/App/SET_DURATION';
export const SET_RELOAD = 'redlights/App/SET_RELOAD';
export const SET_TENANT = 'redlights/App/SET_TENANT';
export const DO_RELOAD = 'redlights/App/DO_RELOAD';
export const UPDATE_THREAT_FIELD = 'redlights/App/UPDATE_THREAT_FIELD';
