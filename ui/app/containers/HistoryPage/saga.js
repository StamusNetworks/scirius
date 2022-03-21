/* eslint-disable */
import * as config from 'config/Api';
import { call, put, takeLatest } from 'redux-saga/effects';

import request from 'ui/utils/request';
import { ACTION_TYPES_LOADING } from "./constants";
import {actionTypesFail, actionTypesSuccess} from "./actions";
import axios from "axios";

export function* getActionTypesList() {
    const requestURL = `${config.API_URL}${config.HISTORY_PATH}get_action_type_list/`;
    try {
        const repos = yield call(axios.get, requestURL);
        yield put(actionTypesSuccess(repos.data.action_type_list));
    } catch (err) {
        yield put(actionTypesFail(err));
    }
}

export default function * root() {
    yield takeLatest(ACTION_TYPES_LOADING, getActionTypesList);
}
