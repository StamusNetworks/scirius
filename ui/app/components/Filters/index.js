import React, { useEffect } from 'react';

import { PushpinOutlined, PushpinFilled } from '@ant-design/icons';
import { Divider, Space, Switch, Affix } from 'antd';
import { toJS } from 'mobx';
import { observer } from 'mobx-react-lite';
import PropTypes from 'prop-types';
import { useHotkeys } from 'react-hotkeys-hook';
import { useDispatch, useSelector } from 'react-redux';
import styled from 'styled-components';

import AdditionalFilters from 'ui/components/AdditionalFilters';
import FilterList from 'ui/components/FilterList/index';
import FiltersDropdown from 'ui/components/FiltersDropdown';
import FilterSetSaveModal from 'ui/components/FilterSetSaveModal';
import Sort from 'ui/components/Sort';
import UICard from 'ui/components/UIElements/UICard';
import UISwitch from 'ui/components/UIElements/UISwitch';
import UISwitchLabel from 'ui/components/UIElements/UISwitchLabel';
import { useStore } from 'ui/mobx/RootStoreProvider';
import ruleSetsActions from 'ui/stores/filters/actions';
import ruleSetReducer from 'ui/stores/filters/reducer';
import ruleSetSaga from 'ui/stores/filters/saga';
import ruleSetsSelectors from 'ui/stores/filters/selectors';
import { useInjectReducer } from 'utils/injectReducer';
import { useInjectSaga } from 'utils/injectSaga';

import Actions from './components/Actions';
import Title from './Title.styled';

const FilterContainer = styled.div`
  display: grid;
  grid-gap: 10px;
  grid-template-columns: 1fr repeat(2, 150px) 10px 150px;
`;

const Separator = styled.div`
  background: #f0f2f5;
  width: 4px;
  margin: -10px 0px -10px -5px;
`;

const Static = styled.div``;

const Filters = ({ page, section, filterTypes = [], onSortChange, sortValues }) => {
  // Component setup
  useInjectReducer({ key: 'ruleSet', reducer: ruleSetReducer });
  useInjectSaga({ key: 'ruleSet', saga: ruleSetSaga });
  const dispatch = useDispatch();
  const { commonStore } = useStore();

  // Selectors handlers
  const { user, filters } = commonStore;
  const saveFiltersModal = useSelector(ruleSetsSelectors.makeSelectSaveFiltersModal());
  const supportedActionsPermissions = user && user.permissions && user.permissions.includes('rules.ruleset_policy_edit');

  // Effects handlers
  useEffect(() => {
    dispatch(ruleSetsActions.ruleSetsRequest());
  }, []);
  useEffect(() => {
    if (supportedActionsPermissions) {
      dispatch(ruleSetsActions.supportedActionsRequest(filters));
    }
  }, [JSON.stringify(filters), supportedActionsPermissions]);

  useHotkeys(
    'shift+i',
    () => {
      commonStore.toggleAlertTag('informational');
    },
    [commonStore.alert.value.informational],
  );
  useHotkeys(
    'shift+r',
    () => {
      commonStore.toggleAlertTag('relevant');
    },
    [commonStore.alert.value.relevant],
  );
  useHotkeys(
    'shift+u',
    () => {
      commonStore.toggleAlertTag('untagged');
    },
    [commonStore.alert.value.untagged],
  );

  const getFiltersCopy = () => {
    const filtersCopy = [
      ...filters.map(f => ({
        fullString: f.fullString,
        id: f.id,
        label: f.label,
        negated: f.negated,
        query: null,
        value: f.value,
      })),
    ];

    if (process.env.REACT_APP_HAS_TAG === '1') {
      filtersCopy.push(toJS(commonStore.alert));
    }
    return filtersCopy;
  };

  const Component = commonStore.stickyFilters ? Affix : Static;

  return (
    <Component offsetTop={10} id="filters-bar">
      <UICard style={{ marginBottom: '10px' }}>
        <FilterContainer>
          <div>
            <Title>
              Filters{' '}
              {commonStore.stickyFilters ? (
                <PushpinFilled
                  data-test="sticky-filters"
                  onClick={() => {
                    commonStore.stickyFilters = false;
                  }}
                />
              ) : (
                <PushpinOutlined
                  onClick={() => {
                    commonStore.stickyFilters = true;
                  }}
                />
              )}
            </Title>
            <FiltersDropdown filterTypes={filterTypes} disabled={page === 'HOST_INSIGHT'} />
            <Divider style={{ margin: '15px 0' }} />
            <FilterList filterTypes={filterTypes} />
          </div>
          <Space direction="vertical">
            {page !== 'HISTORY' && <AdditionalFilters page={page} />}
            {/* 'INVENTORY' should be included when backend is fixed */}
            {['RULES_LIST', 'HOSTS_LIST', 'HISTORY'].indexOf(page) > -1 && (
              <Sort page={page} onChange={(option, direction) => onSortChange(option, direction)} value={sortValues} />
            )}
          </Space>
          <div>
            {page !== 'HISTORY' && commonStore.systemSettings?.license?.nta && (
              <div>
                <Title>Tags Filters</Title>
                <Space direction="vertical">
                  <Space>
                    <UISwitch
                      activeBackgroundColor="#7b1244"
                      size="small"
                      checkedChildren="ON"
                      unCheckedChildren="OFF"
                      checked={commonStore.alert.value.informational}
                      onChange={() => {
                        commonStore.toggleAlertTag('informational');
                      }}
                      disabled={page === 'HOST_INSIGHT'}
                      data-test="Informational-switch"
                    />
                    <UISwitchLabel disabled={page === 'HOST_INSIGHT'}>Informational</UISwitchLabel>
                  </Space>
                  <Space>
                    <UISwitch
                      activeBackgroundColor="#ec7a08"
                      size="small"
                      checkedChildren="ON"
                      unCheckedChildren="OFF"
                      checked={commonStore.alert.value.relevant}
                      onChange={() => {
                        commonStore.toggleAlertTag('relevant');
                      }}
                      disabled={page === 'HOST_INSIGHT'}
                      data-test="Relevant-switch"
                    />
                    <UISwitchLabel disabled={page === 'HOST_INSIGHT'}>Relevant</UISwitchLabel>
                  </Space>
                  <Space>
                    <Switch
                      size="small"
                      checkedChildren="ON"
                      unCheckedChildren="OFF"
                      checked={commonStore.alert.value.untagged}
                      onChange={() => {
                        commonStore.toggleAlertTag('untagged');
                      }}
                      disabled={page === 'HOST_INSIGHT'}
                      data-test="Untagged-switch"
                    />
                    <UISwitchLabel disabled={page === 'HOST_INSIGHT'}>Untagged</UISwitchLabel>
                  </Space>
                </Space>
              </div>
            )}
          </div>
          {page !== 'HISTORY' && <Separator />}
          {page !== 'HISTORY' && <Actions section={section} />}
        </FilterContainer>
        {saveFiltersModal && (
          <FilterSetSaveModal
            title="Create new Filter Set"
            close={() => {
              dispatch(ruleSetsActions.saveFiltersModal(false));
            }}
            fromPage={page}
            content={getFiltersCopy()}
          />
        )}
      </UICard>
    </Component>
  );
};

Filters.propTypes = {
  page: PropTypes.oneOf(['RULES_LIST', 'DASHBOARDS', 'ALERTS_LIST', 'HISTORY', 'HOSTS_LIST', 'INVENTORY']),
  section: PropTypes.string.isRequired,
  filterTypes: PropTypes.array.isRequired,
  onSortChange: PropTypes.func.isRequired,
  sortValues: PropTypes.shape({
    option: PropTypes.string,
    direction: PropTypes.string,
  }),
};

export default observer(Filters);
