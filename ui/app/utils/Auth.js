/* eslint-disable */
// file: src/util/Auth.js
import axios from 'axios';
import _ from 'lodash';
import Modal from 'patternfly-react/dist/esm/components/Modal/Modal';
import store from '../store';
import { setToken } from '../actions';
import { URL, LOGIN } from 'hunt_common/config/Api';

export function InvalidCredentialsException(message) {
    this.message = message;
    this.name = 'InvalidCredentialsException';
}

export function login(username, password) {
    return axios
    .post(URL + LOGIN, {
        username,
        password
    })
    .then((response) => {
        store.dispatch(setToken(response.data.token));
    })
    .catch((error) => {
        // raise different exception if due to invalid credentials
        if (_.get(error, 'response.status') === 400) {
            throw new InvalidCredentialsException(error);
        }
        throw error;
    });
}

export function loggedIn() {
    return store.getState().token == null;
}
