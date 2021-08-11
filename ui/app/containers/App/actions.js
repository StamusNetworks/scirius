/*
 * App Actions
 *
 */

import {
  GET_FAMILIES_REQUEST,
  GET_FAMILIES_SUCCESS,
  GET_FAMILIES_FAILURE,
  GET_ACTIVE_FAMILIES_REQUEST,
  GET_ACTIVE_FAMILIES_SUCCESS,
  GET_ACTIVE_FAMILIES_FAILURE,
  SET_TIME_SPAN,
  SET_DURATION,
  GET_USER_REQUEST,
  GET_USER_SUCCESS,
  GET_USER_FAILURE,
  GET_THREATS_REQUEST,
  GET_THREATS_SUCCESS,
  GET_THREATS_FAILURE,
  GET_ACTIVE_THREATS_REQUEST,
  GET_ACTIVE_THREATS_SUCCESS,
  GET_ACTIVE_THREATS_FAILURE,
  SET_RELOAD,
  SET_TENANT,
  DO_RELOAD,
  GET_TENANTS_REQUEST,
  GET_TENANTS_SUCCESS,
  GET_TENANTS_FAILURE,
  GET_GLOBAL_SETTINGS_REQUEST,
  GET_GLOBAL_SETTINGS_SUCCESS,
  GET_GLOBAL_SETTINGS_FAILURE,
  UPDATE_THREAT_FIELD,
  DELETE_THREAT_REQUEST,
  DELETE_THREAT_SUCCESS,
  DELETE_THREAT_FAILURE,
  GET_SOURCE_REQUEST,
  GET_SOURCE_SUCCESS,
  GET_SOURCE_FAILURE,
} from './constants';

/**
 * Load the repositories, this action starts the request saga
 *
 * @return {object} An action object with a type of LOAD_REPOS
 */
export function getFamilies() {
  return {
    type: GET_FAMILIES_REQUEST,
  };
}

export function getFamiliesSuccess(families) {
  return {
    type: GET_FAMILIES_SUCCESS,
    payload: {
      families,
    },
  };
}

export function getFamiliesFail(httpCode, httpError, httpResponse) {
  return {
    type: GET_FAMILIES_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
  };
}

export function getActiveFamilies() {
  return {
    type: GET_ACTIVE_FAMILIES_REQUEST,
  };
}

export function getActiveFamiliesSuccess(families) {
  return {
    type: GET_ACTIVE_FAMILIES_SUCCESS,
    payload: {
      families,
    },
  };
}

export function getActiveFamiliesFailure(httpCode, httpError, httpResponse) {
  return {
    type: GET_ACTIVE_FAMILIES_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
  };
}

export function getUser() {
  return {
    type: GET_USER_REQUEST,
  };
}

export function getUserSuccess(user) {
  return {
    type: GET_USER_SUCCESS,
    payload: user,
  };
}

export function getUserFailure(httpCode, httpError, httpResponse) {
  return {
    type: GET_USER_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
  };
}

export function getThreats() {
  return {
    type: GET_THREATS_REQUEST,
  };
}

export function getThreatsSuccess(threats) {
  return {
    type: GET_THREATS_SUCCESS,
    payload: {
      threats,
    },
  };
}

export function getThreatsFailure(httpCode, httpError, httpResponse) {
  return {
    type: GET_THREATS_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
  };
}

export function getActiveThreats(familyId) {
  return {
    type: GET_ACTIVE_THREATS_REQUEST,
    payload: {
      familyId,
    },
  };
}

export function getActiveThreatsSuccess(familyId, activeThreats) {
  return {
    type: GET_ACTIVE_THREATS_SUCCESS,
    payload: {
      familyId,
      activeThreats,
    },
  };
}

export function getActiveThreatsFailure(httpCode, httpError, httpResponse, familyId) {
  return {
    type: GET_ACTIVE_THREATS_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
      familyId,
    },
  };
}

export function getGlobalSettings() {
  return {
    type: GET_GLOBAL_SETTINGS_REQUEST,
  };
}

export function getGlobalSettingsSuccess(data) {
  return {
    type: GET_GLOBAL_SETTINGS_SUCCESS,
    payload: {
      data,
    },
  };
}

export function getGlobalSettingsFailure(httpCode, httpError, httpResponse) {
  return {
    type: GET_GLOBAL_SETTINGS_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
  };
}

export function getTenants() {
  return {
    type: GET_TENANTS_REQUEST,
  };
}

export function getTenantsSuccess(tenants) {
  return {
    type: GET_TENANTS_SUCCESS,
    payload: {
      tenants,
    },
  };
}

export function getTenantsFailure(httpCode, httpError, httpResponse) {
  return {
    type: GET_TENANTS_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
  };
}

export function deleteThreat(threatId) {
  return {
    type: DELETE_THREAT_REQUEST,
    payload: {
      threatId,
    },
  };
}

export function deleteThreatSuccess(threatId) {
  return {
    type: DELETE_THREAT_SUCCESS,
    payload: {
      threatId,
    },
  };
}

export function deleteThreatFailure(httpCode, httpError, httpResponse) {
  return {
    type: DELETE_THREAT_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
  };
}

export function getSource() {
  return {
    type: GET_SOURCE_REQUEST,
  };
}

export function getSourceSuccess(source) {
  return {
    type: GET_SOURCE_SUCCESS,
    payload: {
      source,
    },
  };
}

export function getSourceFailure(httpCode, httpError, httpResponse) {
  return {
    type: GET_SOURCE_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
  };
}

export function setTimeSpan(startDate, endDate) {
  return {
    type: SET_TIME_SPAN,
    startDate,
    endDate,
  };
}

export function setDuration(duration) {
  return {
    type: SET_DURATION,
    duration,
  };
}

export function setReload(reloadPeriod) {
  return {
    type: SET_RELOAD,
    payload: {
      reloadPeriod,
    },
  };
}

export function setTenant(tenantId) {
  return {
    type: SET_TENANT,
    payload: {
      tenantId,
    },
  };
}

export function doReload() {
  return {
    type: DO_RELOAD,
  };
}

export function updateThreatField(threatId, field, value) {
  return {
    type: UPDATE_THREAT_FIELD,
    payload: {
      threatId,
      field,
      value,
    },
  };
}
