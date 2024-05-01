import React, { useMemo, useState } from 'react';

import { DownOutlined, TagOutlined } from '@ant-design/icons';
import { Dropdown, Menu } from 'antd';
import { observer } from 'mobx-react-lite';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';

import ErrorHandler from 'ui/components/Error';
import DocDopvModal from 'ui/components/Modal/DocDopvModal';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { useStore } from 'ui/mobx/RootStoreProvider';
import RuleToggleModal from 'ui/RuleToggleModal';
import filtersSelectors from 'ui/stores/filters/selectors';

import { ActionButton } from '../styles';

const ActionsButtons = ({ supportedActions, filterParams, rulesets }) => {
  const { commonStore } = useStore();
  const { filters } = commonStore;
  const stamusMethodFilterApplied = filters.some(filter => filter.id.startsWith('stamus.'));
  const [type, setType] = useState(null);

  const rulesList = {
    pagination: {
      page: 1,
      perPage: 10,
      perPageOptions: [10, 20, 50, 100],
    },
    sort: { id: 'created', asc: false },
  };

  const actions = useMemo(() => {
    let filteredActions = supportedActions;

    if (stamusMethodFilterApplied) {
      filteredActions = supportedActions.filter(([action]) => action !== 'threat');
    }

    if (filteredActions.length > 0 && filteredActions[filteredActions.length - 1][0] === '-') {
      filteredActions.pop();
    }

    return filteredActions.map(([action, label], i) => {
      if (action === '-') {
        // eslint-disable-next-line react/no-array-index-key
        return <Menu.Divider key={`divider${action}${i}`} />;
      }
      return (
        <Menu.Item key={action} data-test={`policy-actions-${action}`} onClick={() => setType(action)}>
          {label}
        </Menu.Item>
      );
    });
  }, [supportedActions, stamusMethodFilterApplied]);

  return (
    <ErrorHandler>
      <ActionButton active={actions.length > 0}>
        <TagOutlined style={{ width: 24 }} />
        <Dropdown overlay={<Menu>{actions}</Menu>} disabled={actions.length === 0} trigger={['hover']}>
          {actions.length === 0 ? (
            <span>Policy Actions</span>
          ) : (
            <a
              onClick={e => e.preventDefault()}
              style={{ display: 'grid', gridTemplateColumns: '1fr min-content', alignItems: 'center' }}
              data-test="policy-actions"
            >
              Policy Actions <DownOutlined />
            </a>
          )}
        </Dropdown>
      </ActionButton>

      <DocDopvModal show={type === 'threat'} close={() => setType(null)} rulesets={rulesets} />

      <RuleToggleModal
        show={type && type !== 'threat'}
        action={type}
        config={rulesList}
        filters={filters}
        close={() => setType(null)}
        rulesets={rulesets}
        systemSettings={commonStore.systemSettings}
        filterParams={filterParams}
        supportedActions={supportedActions}
      />
    </ErrorHandler>
  );
};

ActionsButtons.propTypes = {
  supportedActions: PropTypes.array.isRequired,
  filterParams: PropTypes.any,
  rulesets: PropTypes.any,
};

const mapStateToProps = createStructuredSelector({
  filterParams: makeSelectFilterParams(),
  rulesets: filtersSelectors.makeSelectRuleSets(),
});

const ActionsButtonsObserver = observer(ActionsButtons);

const ConnectedActionsButtons = connect(mapStateToProps)(ActionsButtonsObserver);

export default ConnectedActionsButtons;
