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

import { Table } from 'antd';
import { observer } from 'mobx-react-lite';
import moment from 'moment';
import { useDispatch } from 'react-redux';

import ErrorHandler from 'ui/components/Error';
import Filters from 'ui/components/Filters';
import HistoryItem from 'ui/components/HistoryItem';
import { sections } from 'ui/constants';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import buildListParams from 'ui/helpers/buildListParams';
import { useStore } from 'ui/mobx/RootStoreProvider';
import filtersActions from 'ui/stores/filters/actions';
import reducer from 'ui/stores/filters/reducer';
import saga from 'ui/stores/filters/saga';
import history from 'ui/utils/history';
import { useInjectReducer } from 'ui/utils/injectReducer';
import { useInjectSaga } from 'ui/utils/injectSaga';

import { buildFilter, buildListUrlParams } from '../../helpers/common';
import HuntPaginationRow from '../../HuntPaginationRow';

const HistoryPage = () => {
  useInjectSaga({ key: 'ruleSet', saga });
  useInjectReducer({ key: 'ruleSet', reducer });
  const { commonStore, historyStore } = useStore();

  const dispatch = useDispatch();

  const [loading, setLoading] = useState(false);
  const [data, setData] = useState([]);
  const [count, setCount] = useState(0);
  const [historyState, setHistoryState] = useState(
    buildListParams(JSON.parse(localStorage.getItem('history')), {
      pagination: {
        page: 1,
        perPage: 10,
        perPageOptions: [10, 20, 50, 100],
      },
      sort: { id: 'date', asc: false },
    }),
  );

  useEffect(() => {
    dispatch(filtersActions.historyFiltersRequest());
  }, []);

  const stringFilters = buildFilter(commonStore.history, commonStore.systemSettings);
  const listParams = buildListUrlParams(historyState);

  useEffect(() => {
    (async () => {
      setLoading(true);
      const response = await historyStore.fetchData(stringFilters, listParams);
      setData(response?.results || []);
      setCount(response?.count || 0);
      setLoading(false);
    })();
  }, [stringFilters, listParams]);

  const updateHistoryListState = historyState => {
    setHistoryState(historyState);
    localStorage.setItem('history', JSON.stringify(historyState));
  };

  const columns = [
    {
      title: 'Operation',
      dataIndex: 'title',
    },
    {
      title: 'Message',
      dataIndex: 'description',
    },
    {
      title: 'Date',
      dataIndex: 'date',
      render: value => moment(value).format('YYYY-MM-DD, hh:mm:ss a'),
    },
    {
      title: 'User',
      dataIndex: 'username',
    },
    {
      title: 'IP',
      dataIndex: 'client_ip',
    },
    {
      title: 'Ruleset',
      dataIndex: ['ua_objects', 'ruleset', 'value'],
    },
    {
      title: 'Signature',
      render: value =>
        value.ua_objects.rule?.sid && (
          <a
            onClick={() => {
              dispatch(addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: value.ua_objects.rule.sid, negated: false }));
              history.push('/stamus/hunting/signatures', value.ua_objects.rule.sid);
            }}
          >
            {value.ua_objects.rule.sid}
          </a>
        ),
    },
  ];

  return (
    <div>
      <ErrorHandler>
        <Filters
          page="HISTORY"
          filterTypes={['HISTORY']}
          sortValues={{ option: historyState.sort.id, direction: historyState.sort.asc ? 'asc' : 'desc' }}
          onSortChange={(option, direction) => {
            updateHistoryListState({
              ...historyState,
              sort: {
                id: option || historyState.sort.id,
                asc: direction ? direction === 'asc' : historyState.sort.asc,
              },
            });
          }}
        />
      </ErrorHandler>
      {data && (
        <Table
          rowKey={item => item.pk}
          size="small"
          loading={loading}
          dataSource={data}
          columns={columns}
          expandable={{
            columnWidth: 5,
            expandRowByClick: true,
            expandedRowRender: item => <HistoryItem key={item.pk} data={item} />,
            rowExpandable: () => true,
          }}
          pagination={false}
        />
      )}
      <ErrorHandler>
        <HuntPaginationRow onPaginationChange={updateHistoryListState} itemsCount={count} itemsList={historyState} />
      </ErrorHandler>
    </div>
  );
};

export default observer(HistoryPage);
