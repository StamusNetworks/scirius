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

import React, { useEffect, useState } from 'react';
import { Dropdown, Menu, Row, Col } from 'antd';
import { MenuOutlined } from '@ant-design/icons';
import store from 'store';
import { Helmet } from 'react-helmet';
import { STAMUS } from 'ui/config';
import { useSelector } from 'react-redux';
import { sections } from 'ui/constants';
import ErrorHandler from 'ui/components/Error';
import Filters from 'ui/components/Filters';
import { useStore } from 'ui/mobx/RootStoreProvider';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { makeSelectGlobalFilters, makeSelectUserData } from 'ui/containers/HuntApp/stores/global';
import HuntTimeline from 'ui/HuntTimeline';
import HuntTrend from 'ui/HuntTrend';
import 'react-resizable/css/styles.css';
import '../../../../rules/static/rules/c3.min.css';
import DashboardMosaic from '../../components/DashboardMosaic';

const DashboardPage = () => {
  const { commonStore } = useStore();
  const filtersWithAlert = useSelector(makeSelectGlobalFilters(true));
  const filterParams = useSelector(makeSelectFilterParams());
  const user = useSelector(makeSelectUserData());
  const [chartTarget, setChartTarget] = useState(store.get('chartTarget') === true);
  const hasPermissions = user.permissions.includes('rules.configuration_view');

  useEffect(() => {
    store.set('chartTarget', chartTarget);
  }, [chartTarget]);

  const menu = (
    <Menu>
      <Menu.Item onClick={() => setChartTarget(!chartTarget)} data-toggle="modal">
        Switch timeline by probes/tags
      </Menu.Item>
    </Menu>
  );

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
            filterParams={filterParams}
            chartTarget={chartTarget}
            filters={filtersWithAlert}
            systemSettings={commonStore.systemSettings}
          />
        </Col>
        <Col lg={4} md={6} sm={24} xs={24} style={{ paddingLeft: '0px' }}>
          <HuntTrend filterParams={filterParams} filters={filtersWithAlert} systemSettings={commonStore.systemSettings} />
          {hasPermissions && (process.env.REACT_APP_HAS_TAG === '1' || process.env.NODE_ENV === 'development') && (
            <div style={{ position: 'absolute', zIndex: 1, top: 0, right: '30px' }}>
              <Dropdown id="more-actions" overlay={menu} trigger={['click']}>
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
};

export default DashboardPage;
