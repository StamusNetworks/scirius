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

import React from 'react';
import PropTypes from 'prop-types';
import { Dropdown, Menu, Row, Col } from 'antd';
import { MenuOutlined } from '@ant-design/icons';
import store from 'store';
import { Helmet } from 'react-helmet';
import { STAMUS } from 'ui/config';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { compose } from 'redux';
import { sections } from 'ui/constants';
import ErrorHandler from 'ui/components/Error';
import Filters from 'ui/components/Filters';
import globalSelectors from 'ui/containers/App/selectors';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { withPermissions } from 'ui/containers/HuntApp/stores/withPermissions';
import HuntTimeline from '../../HuntTimeline';
import HuntTrend from '../../HuntTrend';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';
import { makeSelectAlertTag, makeSelectGlobalFilters } from '../../containers/HuntApp/stores/global';
import '../../../../rules/static/rules/c3.min.css';
import DashboardMosaic from '../../components/DashboardMosaic';

export class HuntDashboard extends React.Component {
  constructor(props) {
    super(props);

    let chartTarget = store.get('chartTarget') === true;

    if (!chartTarget && !this.props.user.permissions.includes('rules.configuration_view')) {
      chartTarget = true;
    }

    this.state = { chartTarget };
  }

  onChangeChartTarget = chartTarget => {
    this.setState({
      chartTarget,
    });

    store.set('chartTarget', chartTarget);
  };

  menu = (
    <Menu>
      <Menu.Item onClick={() => this.onChangeChartTarget(!this.state.chartTarget)} data-toggle="modal">
        Switch timeline by probes/tags
      </Menu.Item>
    </Menu>
  );

  render() {
    return (
      <div>
        <Helmet>
          <title>{`${STAMUS} - Dashboards`}</title>
        </Helmet>

        <ErrorHandler>
          <Filters page="DASHBOARDS" section={sections.GLOBAL} queryTypes={['filter', 'filter_host_id']} filterTypes={['filter']} />
        </ErrorHandler>

        <Row style={{ marginTop: 10 }}>
          <Col lg={20} md={18} sm={24} xs={24} style={{ paddingRight: '0px' }}>
            <HuntTimeline
              style={{ marginTop: '15px' }}
              filterParams={this.props.filterParams}
              chartTarget={this.state.chartTarget}
              filters={this.props.filtersWithAlert}
              systemSettings={this.props.systemSettings}
            />
          </Col>
          <Col lg={4} md={6} sm={24} xs={24} style={{ paddingLeft: '0px' }}>
            <HuntTrend filterParams={this.props.filterParams} filters={this.props.filtersWithAlert} systemSettings={this.props.systemSettings} />
            {typeof this.state.chartTarget !== 'undefined' && (process.env.REACT_APP_HAS_TAG === '1' || process.env.NODE_ENV === 'development') && (
              <div style={{ position: 'absolute', zIndex: 10, top: 0, right: '30px' }}>
                <Dropdown id="more-actions" overlay={this.menu} trigger={['click']}>
                  <a className="ant-dropdown-link" onClick={e => e.preventDefault()}>
                    <MenuOutlined />
                  </a>
                </Dropdown>
              </div>
            )}
          </Col>
        </Row>
        <div>
          <div className="clearfix" />
          <DashboardMosaic />
        </div>
      </div>
    );
  }
}

HuntDashboard.propTypes = {
  systemSettings: PropTypes.any,
  filtersWithAlert: PropTypes.array,
  filterParams: PropTypes.object.isRequired,
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

const mapStateToProps = createStructuredSelector({
  filtersWithAlert: makeSelectGlobalFilters(true),
  alertTag: makeSelectAlertTag(),
  filterParams: makeSelectFilterParams(),
  systemSettings: globalSelectors.makeSelectSystemSettings(),
});

const withConnect = connect(mapStateToProps);
export default compose(withPermissions, withConnect)(HuntDashboard);
