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

import React, { useState } from 'react';
import { Table } from 'antd';
import { BellFilled } from '@ant-design/icons';
import { Helmet } from 'react-helmet';
import { observer } from 'mobx-react-lite';
import { STAMUS } from 'ui/config';
import { buildQFilter } from 'ui/buildQFilter';
import ErrorHandler from 'ui/components/Error';
import HuntRestError from 'ui/components/HuntRestError';
import { sections } from 'ui/constants';
import Filters from 'ui/components/Filters';
import moment from 'moment';
import buildListParams from 'ui/helpers/buildListParams';
import { useStore } from 'ui/mobx/RootStoreProvider';
import useAutorun from 'ui/helpers/useAutorun';
import useFilterParams from 'ui/hooks/useFilterParams';
import { buildListUrlParams } from '../../helpers/common';
import AlertItem from './components/AlertItem';
import HuntPaginationRow from '../../HuntPaginationRow';

const EventsPage = () => {
  const { commonStore, esStore } = useStore();
  const filterParams = useFilterParams();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState(null);
  const [count, setCount] = useState(0);
  const [alertsList, setAlertList] = useState(
    buildListParams(JSON.parse(localStorage.getItem('alerts_list')), {
      pagination: {
        page: 1,
        perPage: 10,
        perPageOptions: [10, 20, 50, 100],
      },
      sort: { id: 'timestamp', asc: false },
      view_type: 'list',
    }),
  );

  const updateRuleListState = rulesListState => {
    setAlertList(rulesListState);
    localStorage.setItem('alerts_list', JSON.stringify(rulesListState));
  };

  const qfilter = buildQFilter(commonStore.filtersWithAlert, commonStore.systemSettings);
  const paginationParams = buildListUrlParams(alertsList);

  const fetchData = async () => {
    try {
      const data = await esStore.fetchAlertsTail(paginationParams, qfilter);
      if (data !== null && data.results && typeof data.results !== 'string') {
        setAlerts(data.results);
        setCount(data.count);
        setLoading(false);
      } else {
        setLoading(false);
      }
    } catch (error) {
      if (error.response.status === 500) {
        setErrors([`${error.response.data[0].slice(0, 160)}...`]);
        setLoading(false);
        return;
      }
      setErrors([]);
      setLoading(false);
    }
  };

  useAutorun(fetchData, [], [qfilter, paginationParams]);

  const getIconColor = key => {
    if (key === 'informational') return '#7b1244';
    if (key === 'relevant') return '#ec7a08';
    return '#005792';
  };

  const columns = [
    {
      title: '',
      render: (e, row) => (
        <div>
          <BellFilled style={{ color: getIconColor(row.tag) }} />
        </div>
      ),
    },
    {
      title: 'Timestamp',
      dataIndex: 'timestamp',
    },
    {
      title: 'Method',
      dataIndex: 'method',
    },
    {
      title: 'Source IP',
      dataIndex: 'source_ip',
    },
    {
      title: 'Destination IP',
      dataIndex: 'destination_ip',
    },
    {
      title: 'Proto',
      dataIndex: 'proto',
    },
    {
      title: 'Probe',
      dataIndex: 'probe',
    },
    {
      title: 'Category',
      dataIndex: 'category',
    },
    {
      title: 'Tag',
      dataIndex: 'tag',
    },
  ];

  const dataSource = alerts.map(rule => ({
    key: rule._id,
    timestamp: moment(rule.timestamp).format('YYYY-MM-DD, hh:mm:ss a'),
    method: rule.alert.signature,
    source_ip: rule.src_ip,
    destination_ip: rule.dest_ip,
    proto: rule.app_proto || rule.proto,
    probe: rule.host,
    category: rule.alert.category,
    tag: rule.alert.tag || 'untagged',
    rule, // we need this to access the rule data in the `expandedRowRender` below
  }));

  return (
    <div>
      <Helmet>
        <title>{`${STAMUS} - Events`}</title>
      </Helmet>

      {errors && <HuntRestError errors={errors} />}
      <ErrorHandler>
        <Filters page="ALERTS_LIST" section={sections.GLOBAL} queryTypes={['filter', 'filter_host_id']} filterTypes={['filter']} />
      </ErrorHandler>

      <Table
        data-test="alerts-table"
        size="small"
        loading={loading}
        dataSource={dataSource}
        columns={columns}
        expandable={{
          columnWidth: 5,
          expandRowByClick: true,
          expandedRowRender: alert => <AlertItem data={alert.rule} filterParams={filterParams} eventTypes={commonStore.eventTypes} />,
          rowExpandable: () => true,
        }}
        pagination={false}
      />

      <ErrorHandler>
        <HuntPaginationRow viewType="list" onPaginationChange={updateRuleListState} itemsCount={count} itemsList={alertsList} />
      </ErrorHandler>
    </div>
  );
};

export default observer(EventsPage);
