/* eslint-disable */
// file: src/util/ApiClient.js
import axios from 'axios';
import store from '../store';
import { URL } from 'hunt_common/config/Api';

export const apiClient = function () {
    const { token } = store.getState();
    const params = {
        baseURL: URL,
        headers: { Authorization: `Token ${token}` }
    };
    return axios.create(params);
};
