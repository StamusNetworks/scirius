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
import { sections } from 'ui/constants';
import Filters from 'ui/components/Filters';
import HistoryItem from 'ui/components/HistoryItem';
import ErrorHandler from 'ui/components/Error';
import moment from 'moment';
import buildListParams from 'ui/helpers/buildListParams';
import { useDispatch, useSelector } from 'react-redux';
import { useInjectSaga } from 'ui/utils/injectSaga';
import { useInjectReducer } from 'ui/utils/injectReducer';
import filtersActions from 'ui/stores/filters/actions';
import reducer from 'ui/stores/filters/reducer';
import saga from 'ui/stores/filters/saga';
import { addFilter, makeSelectHistoryFilters } from 'ui/containers/HuntApp/stores/global';
import history from 'ui/utils/history';
import { useStore } from 'ui/mobx/RootStoreProvider';
import { buildFilter, buildListUrlParams } from '../../helpers/common';
import HuntPaginationRow from '../../HuntPaginationRow';

const HistoryPage = () => {
  useInjectSaga({ key: 'ruleSet', saga });
  useInjectReducer({ key: 'ruleSet', reducer });
  const { commonStore, historyStore } = useStore();

  const dispatch = useDispatch();

  const [loading, setLoading] = useState(false);
  const [historyState, setHistoryState] = useState(
    buildListParams(JSON.parse(localStorage.getItem('history')), {
      pagination: {
        page: 1,
        perPage: 10,
        perPageOptions: [10, 20, 50, 100],
      },
      sort: { id: 'date', asc: false },
      view_type: 'list',
    }),
  );

  useEffect(() => {
    dispatch(filtersActions.historyFiltersRequest());
  }, []);

  const filters = useSelector(makeSelectHistoryFilters());

  const stringFilters = buildFilter(filters, commonStore.systemSettings);
  const listParams = buildListUrlParams(historyState);

  useEffect(async () => {
    setLoading(true);
    await historyStore.fetchData(stringFilters, listParams);
    setLoading(false);
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
          section={sections.HISTORY}
          queryTypes={['all']}
          filterTypes={['all']}
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
      {historyStore.historyItemsList && (
        <Table
          rowKey={item => item.pk}
          size="small"
          loading={loading}
          dataSource={historyStore.historyItemsList}
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
        <HuntPaginationRow
          viewType="list"
          onPaginationChange={updateHistoryListState}
          itemsCount={historyStore.historyItemsCount}
          itemsList={historyState}
        />
      </ErrorHandler>
    </div>
  );
};

export default observer(HistoryPage);
