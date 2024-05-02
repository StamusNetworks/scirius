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

import { DeleteOutlined, InfoCircleOutlined, LoadingOutlined } from '@ant-design/icons';
import { Drawer, Collapse, Empty, Modal } from 'antd';
import { useHotkeys } from 'react-hotkeys-hook';
import { useDispatch, useSelector } from 'react-redux';
import styled from 'styled-components';

import FilterSetItem from 'ui/components/FilterSetItem';
import FilterSetSearch from 'ui/components/FilterSetSearch';
import LoadingIndicator from 'ui/components/LoadingIndicator';
import { sections, huntUrls } from 'ui/constants';
import actions from 'ui/containers/App/actions';
import selectors from 'ui/containers/App/selectors';
import { addFilter, clearFilters, setTag } from 'ui/containers/HuntApp/stores/global';
import { useCustomHistory } from 'ui/hooks/useCustomHistory';
import { useStore } from 'ui/mobx/RootStoreProvider';
import filterSetActions from 'ui/stores/filterset/actions';
import reducer from 'ui/stores/filterset/reducer';
import saga from 'ui/stores/filterset/saga';
import filterSetSelectors from 'ui/stores/filterset/selectors';
import Filter from 'ui/utils/Filter';
import { useInjectReducer } from 'ui/utils/injectReducer';
import { useInjectSaga } from 'ui/utils/injectSaga';

const NoResults = styled.div`
  color: #6d6d6d;
  margin-bottom: 10px;
  font-style: italic;
  text-align: center;
`;

const Panel = styled(Collapse.Panel)`
  .ant-collapse-content-box {
    padding: 0;
  }
`;

const FilterSets = () => {
  useInjectReducer({ key: 'filterSets', reducer });
  useInjectSaga({ key: 'filterSets', saga });
  const dispatch = useDispatch();
  const { commonStore } = useStore();
  const history = useCustomHistory();

  const [expandedPanels, setExpandedPanels] = useState([]);
  const [searchValue, setSearchValue] = useState('');

  const globalSet = useSelector(filterSetSelectors.makeSelectGlobalFilterSets());
  const privateSet = useSelector(filterSetSelectors.makeSelectPrivateFilterSets());
  const staticSet = useSelector(filterSetSelectors.makeSelectStaticFilterSets());
  const { loading } = useSelector(filterSetSelectors.makeSelectFilterSetsRequest('get'));
  const { loading: deleteLoading } = useSelector(filterSetSelectors.makeSelectFilterSetsRequest('delete'));
  const confirmDelete = useSelector(filterSetSelectors.makeSelectDeleteFilterSetId());
  const visible = useSelector(selectors.makeSelectFilterSetsState());

  useEffect(() => {
    if (visible) {
      dispatch(filterSetActions.loadFilterSetsRequest());
    }
  }, [visible]);

  useHotkeys(
    'escape',
    () => {
      if (visible) dispatch(actions.setFilterSets(false));
    },
    [],
  );

  const loadFilterSets = row => {
    dispatch(clearFilters(sections.GLOBAL));

    const filters = row.content.filter(f => f.id !== 'alert.tag');
    dispatch(addFilter(sections.GLOBAL, filters));
    commonStore.setFilters(
      filters.map(f => new Filter(f.id, f.value, { negated: f.negated || false, fullString: f.fullString !== undefined ? f.fullString : true })),
    );
    if (row.page === 'RULES_LIST' && filters.find(f => f.id === 'hits_min')) {
      commonStore.withAlerts = true;
    }

    if (process.env.REACT_APP_HAS_TAG) {
      const alertTag = row.content.filter(f => f.id === 'alert.tag')[0];
      dispatch(setTag(alertTag));
    }

    history.push(`/stamus/${huntUrls[row.page]}`);
    dispatch(actions.doReload());
    dispatch(actions.setFilterSets(false));
  };

  const rowsGlobal = globalSet?.filter(item => item.name.toLowerCase().includes(searchValue.toLowerCase())) || [];
  const rowsPrivate = privateSet?.filter(item => item.name.toLowerCase().includes(searchValue.toLowerCase())) || [];
  const rowsStatic = staticSet?.filter(item => item.name.toLowerCase().includes(searchValue.toLowerCase())) || [];
  const hasRights = commonStore.user?.isActive && commonStore.user?.permissions.includes('rules.events_edit');

  const map = [
    {
      type: 'global',
      title: 'Global Filter Sets',
      data: rowsGlobal,
      delete: true,
    },
    {
      type: 'private',
      title: 'Private Filter Sets',
      data: rowsPrivate,
      delete: true,
    },
    {
      type: 'static',
      title: 'Stamus Predefined Filter Sets',
      data: rowsStatic,
      delete: false,
    },
  ];

  const totalResults = rowsGlobal.length + rowsPrivate.length + rowsStatic.length;

  return (
    <Drawer visible={visible} onClose={() => dispatch(actions.setFilterSets(false))} title="Filter Sets" placement="right" zIndex={10000} width={450}>
      <FilterSetSearch onChange={value => setSearchValue(value)} disabled={loading} value={searchValue} />
      {!loading && totalResults === 0 && (
        <NoResults>
          <InfoCircleOutlined /> No results match your search criteria
        </NoResults>
      )}
      <Collapse
        onChange={key => setExpandedPanels(key)}
        activeKey={
          searchValue.length > 0
            ? [rowsGlobal.length > 0 ? 'global' : null, rowsPrivate.length > 0 ? 'private' : null, rowsStatic.length > 0 ? 'static' : null]
            : expandedPanels
        }
      >
        {map.map(item => (
          <Panel
            data-test={`${item.type}-filtersets`}
            key={item.type}
            header={item.title}
            extra={
              loading ? (
                <LoadingIndicator style={{ width: 22, height: 22, margin: 0 }} />
              ) : (
                <span data-test={`${item.title.toLowerCase().replaceAll(' ', '-')}-count`}>{`${item.data.length} Filter Sets`}</span>
              )
            }
          >
            {item.data.length === 0 && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
            {item.data.map(filterSetItem => (
              <FilterSetItem
                key={`${item.type}-${filterSetItem?.id}-${deleteLoading.toString()}`}
                item={filterSetItem}
                loadFilterSets={() => loadFilterSets(filterSetItem)}
                onDelete={item.delete ? () => dispatch(filterSetActions.deleteFilterSetConfirm(filterSetItem.id)) : undefined}
                hasRights={hasRights}
                loading={deleteLoading && confirmDelete === filterSetItem.id}
                type={item.type}
              />
            ))}
          </Panel>
        ))}
      </Collapse>
      <Modal
        title="Deleting a filter set"
        visible={Boolean(confirmDelete)}
        zIndex={11000}
        onCancel={() => dispatch(filterSetActions.deleteFilterSetConfirm(undefined))}
        onOk={() => {
          dispatch(filterSetActions.deleteFilterSetRequest(confirmDelete));
        }}
        cancelButtonProps={{ disabled: deleteLoading }}
        okButtonProps={{
          danger: true,
          disabled: deleteLoading,
          'data-test': 'confirm-delete-filterset',
          icon: deleteLoading ? <LoadingOutlined /> : <DeleteOutlined />,
        }}
        okText={deleteLoading ? 'Please wait...' : 'Delete'}
      >
        Delete this filter set?
      </Modal>
    </Drawer>
  );
};

export default FilterSets;
