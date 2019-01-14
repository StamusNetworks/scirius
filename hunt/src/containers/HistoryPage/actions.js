import { ACTION_TYPES_LOADING, ACTION_TYPES_SUCCESS, ACTION_TYPES_FAIL } from './constants';

export function actionTypes() {
    return {
        type: ACTION_TYPES_LOADING,
    };
}

export function actionTypesSuccess(actionTypesList) {
    return {
        type: ACTION_TYPES_SUCCESS,
        actionTypesList
    };
}

export function actionTypesFail() {
    return {
        type: ACTION_TYPES_FAIL,
    };
}
