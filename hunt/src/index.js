import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import HuntApp from './App';
import registerServiceWorker from './registerServiceWorker';

ReactDOM.render(<HuntApp />, document.getElementById('root'));
registerServiceWorker();
