import configureStore from './configureStore';
import history from './utils/history';
const store = configureStore({}, history);
export default store;
