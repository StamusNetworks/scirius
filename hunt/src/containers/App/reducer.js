import { fromJS } from 'immutable';

import { PLACEHOLDER } from './constants';

// The initial state of the App. This is the global reducer
const initialState = fromJS({
    placeholder: false,
});

function appReducer(state = initialState, action) {
    switch (action.type) {
        case PLACEHOLDER:
            return state
            .set('PLACEHOLDER', true);
        default:
            return state;
    }
}

export default appReducer;
