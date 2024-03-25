import React, { useMemo, useState } from 'react';

import { DownOutlined, TagOutlined } from '@ant-design/icons';
import { Dropdown, Menu } from 'antd';
import { observer } from 'mobx-react-lite';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';

import ErrorHandler from 'ui/components/Error';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { useStore } from 'ui/mobx/RootStoreProvider';
import RuleToggleModal from 'ui/RuleToggleModal';
import filtersSelectors from 'ui/stores/filters/selectors';

import { ActionButton } from '../styles';

const ActionsButtons = ({ supportedActions, filterParams, rulesets }) => {
  const { commonStore } = useStore();
  const { filters } = commonStore;
  const stamusMethodFilterApplied = filters.some(filter => filter.id.startsWith('stamus.'));
  const [visible, setVisible] = useState(false);
  const [type, setType] = useState(false);
  const rulesList = {
    pagination: {
      page: 1,
      perPage: 10,
      perPageOptions: [10, 20, 50, 100],
    },
    sort: { id: 'created', asc: false },
  };

  const actions = useMemo(() => {
    const result = [];
    for (let i = 0; i < supportedActions.length; i += 1) {
      const action = supportedActions[i];

      // eslint-disable-next-line no-continue
      if (stamusMethodFilterApplied && action[1] === 'Create DoC events') continue;

      if (action[0] === '-') {
        result.push(<Menu.Divider key={`divider-${i}`} />);
      } else {
        result.push(
          <Menu.Item
            key={action[0]}
            data-test={`policy-actions-${action[1].toLowerCase().replaceAll(' ', '-')}`}
            onClick={() => {
              setVisible(true);
              setType(action[0]);
            }}
          >
            {action[1]}
          </Menu.Item>,
        );
      }
    }
    return result;
  }, [supportedActions]);

  if (process.env.REACT_APP_HAS_ACTION === '1' || process.env.NODE_ENV === 'development') {
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
        <RuleToggleModal
          show={visible}
          action={type}
          config={rulesList}
          filters={filters}
          close={() => setVisible(false)}
          rulesets={rulesets}
          systemSettings={commonStore.systemSettings}
          filterParams={filterParams}
          supportedActions={supportedActions}
        />
      </ErrorHandler>
    );
  }
  return <div />;
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

// export default connect(mapStateToProps)(ActionsButtons);

const ActionsButtonsObserver = observer(ActionsButtons);

const Wrapper = props => <ActionsButtonsObserver {...props} />;

export default connect(mapStateToProps)(Wrapper);
