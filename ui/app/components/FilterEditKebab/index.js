/* eslint-disable react/no-access-state-in-setstate */
import React, { useState, useCallback } from 'react';

import { MenuOutlined } from '@ant-design/icons';
import { Dropdown, Menu } from 'antd';
import { observer } from 'mobx-react-lite';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { compose } from 'redux';
import { createStructuredSelector } from 'reselect';

import ErrorHandler from 'ui/components/Error';
import FilterSetSaveModal from 'ui/components/FilterSetSaveModal';
import { sections } from 'ui/constants';
import { addFilter, generateAlert, setTag, clearFilters, makeSelectAlertTag } from 'ui/containers/HuntApp/stores/global';
import FilterToggleModal from 'ui/FilterToggleModal';
import { useCustomHistory } from 'ui/hooks/useCustomHistory';
import { useStore } from 'ui/mobx/RootStoreProvider';
import filterSetActions from 'ui/stores/filterset/actions';
import Filter from 'ui/utils/Filter';

const FilterEditKebab = observer(({ data, lastIndex, needUpdate, setExpand, alertTag, setTag, clearFilters }) => {
  const [toggle, setToggle] = useState({ show: false, action: 'delete' });
  const [filterSets, setFilterSets] = useState({ showModal: false, page: '', shared: false, name: '', description: '' });
  const { commonStore } = useStore();

  const history = useCustomHistory();

  const displayToggle = useCallback(
    action => {
      setToggle({ show: true, action });
      setExpand(false);
    },
    [setExpand],
  );

  const closeAction = useCallback(() => {
    setToggle({ show: false, action: 'delete' });
    setExpand(true);
  }, [setExpand]);

  const closeActionToFilterSet = () => {
    setFilterSets({ showModal: false, shared: false, page: 'DASHBOARDS', name: '', errors: undefined, description: '' });
  };

  const generateAlertTag = () => {
    const { action } = data;
    return process.env.REACT_APP_HAS_TAG === '1' && (action === 'tag' || action === 'tagkeep')
      ? generateAlert(true, true, true, true, true)
      : alertTag;
  };

  const generateFilterSet = () =>
    data.filter_defs.map(filterDef => {
      const val = Number(filterDef.value) || filterDef.value;
      const filter = new Filter(filterDef.key, val, {
        negated: filterDef.operator !== 'equal',
        fullString: filterDef.full_string,
      });
      return {
        id: filter.id,
        key: filter.id,
        label: filter.label,
        value: filter.value,
        negated: filter.negated,
        fullString: filter.fullString,
      };
    });

  const saveActionToFilterSet = () => {
    setFilterSets({ showModal: true, page: 'DASHBOARDS', shared: false, name: '', description: '' });
    setExpand(false);
  };

  const convertActionToFilters = () => {
    clearFilters(sections.GLOBAL);
    commonStore.addFilter(generateFilterSet());
    if (process.env.REACT_APP_HAS_TAG === '1') {
      setTag(generateAlertTag());
    }
    history.push(`/stamus/hunting/dashboards`);
  };

  return (
    <React.Fragment>
      {filterSets.showModal && (
        <FilterSetSaveModal title="Create new Filter Set From Action" close={closeActionToFilterSet} content={generateFilterSet()} />
      )}
      <Dropdown
        id="filterActions"
        overlay={
          <Menu onClick={({ domEvent }) => domEvent.stopPropagation()}>
            {commonStore.user?.isActive && commonStore.user?.permissions.includes('rules.events_edit') && (
              <React.Fragment>
                {data.index !== 0 && (
                  <Menu.Item key="1" data-test="send-action-to-top" onClick={() => displayToggle('movetop')}>
                    Send Action to top
                  </Menu.Item>
                )}
                <Menu.Item key="2" data-test="move-action" onClick={() => displayToggle('move')}>
                  Move Action
                </Menu.Item>
                <Menu.Item key="3" data-test="send-action-to-bottom" onClick={() => displayToggle('movebottom')}>
                  Send Action to bottom
                </Menu.Item>
                <Menu.Item key="4" data-test="delete-action" onClick={() => displayToggle('delete')}>
                  Delete Action
                </Menu.Item>
              </React.Fragment>
            )}
            <Menu.Item key="5" data-test="convert-action-to-filters" onClick={convertActionToFilters}>
              Convert Action to Filters
            </Menu.Item>
            {commonStore.user?.isActive && (
              <Menu.Item key="6" data-test="save-action-as-filter-set" onClick={saveActionToFilterSet}>
                Save Action as Filter set
              </Menu.Item>
            )}
          </Menu>
        }
        trigger={['click']}
      >
        <a
          className="ant-dropdown-link"
          data-test={`kebab-dropdown-${data.index}`}
          onClick={e => {
            e.preventDefault();
            e.stopPropagation();
          }}
        >
          <MenuOutlined />
        </a>
      </Dropdown>
      <ErrorHandler>
        <FilterToggleModal show={toggle.show} action={toggle.action} data={data} close={closeAction} last_index={lastIndex} needUpdate={needUpdate} />
      </ErrorHandler>
    </React.Fragment>
  );
});

FilterEditKebab.propTypes = {
  data: PropTypes.any,
  lastIndex: PropTypes.any,
  needUpdate: PropTypes.any,
  setTag: PropTypes.func,
  clearFilters: PropTypes.func,
  alertTag: PropTypes.object,
  setExpand: PropTypes.func,
};

const mapStateToProps = createStructuredSelector({
  alertTag: makeSelectAlertTag(),
});

const mapDispatchToProps = {
  loadFilterSetsRequest: filterSetActions.loadFilterSetsRequest,
  addFilter,
  clearFilters,
  setTag,
};

const withConnect = connect(mapStateToProps, mapDispatchToProps);
export default compose(withConnect)(FilterEditKebab);
