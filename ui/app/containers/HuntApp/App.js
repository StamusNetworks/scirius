/*
Copyright(C) 2018 Stamus Networks
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

import React, { Component } from 'react';
import { ShortcutManager } from 'react-shortcuts';
import PropTypes from 'prop-types';
import axios from 'axios';
import ErrorHandler from 'ui/components/Error';
import DisplayPage from 'ui/components/DisplayPage';
import * as config from 'config/Api';
import EmitEvent from '../../helpers/EmitEvent';
import keymap from '../../Keymap';

const shortcutManager = new ShortcutManager(keymap);

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';

export default class HuntApp extends Component {
  constructor(props) {
    super(props);
    this.timer = null;
    this.state = {};
  }

  getChildContext() {
    return { shortcuts: shortcutManager };
  }

  componentDidMount() {
    axios.get(config.API_URL + config.SYSTEM_SETTINGS_PATH).then(systemSettings => {
      this.setState({ systemSettings: systemSettings.data });
    });
  }

  adjustDashboardWidth = () => {
    setTimeout(() => {
      EmitEvent('resize');
      EmitEvent('resize');
    }, 150);
  };

  render() {
    return (
      <div className="layout-pf layout-pf-fixed faux-layout">
        <div className="container-fluid container-pf-nav-pf-vertical nav-pf-persistent-secondary">
          <div className="row row-cards-pf">
            <div className="col-xs-12 col-sm-12 col-md-12 no-col-gutter-right" id="app-content">
              <ErrorHandler>
                <DisplayPage page={this.props.page} systemSettings={this.state.systemSettings} />
              </ErrorHandler>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

HuntApp.childContextTypes = {
  shortcuts: PropTypes.object.isRequired,
};

HuntApp.propTypes = {
  page: PropTypes.string.isRequired,
  user: PropTypes.shape({
    pk: PropTypes.any,
    timezone: PropTypes.any,
    username: PropTypes.any,
    firstName: PropTypes.any,
    lastName: PropTypes.any,
    isActive: PropTypes.any,
    email: PropTypes.any,
    dateJoined: PropTypes.any,
    permissions: PropTypes.any,
  }),
};
