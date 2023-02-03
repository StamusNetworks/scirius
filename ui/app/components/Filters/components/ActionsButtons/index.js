import React, { useEffect, useMemo, useState } from 'react';
import { Dropdown, Menu } from 'antd';
import { DownOutlined, TagOutlined } from '@ant-design/icons';
import RuleToggleModal from 'ui/RuleToggleModal';
import PropTypes from 'prop-types';
import request from 'ui/utils/request';
import * as config from 'config/Api';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import filtersSelectors from 'ui/stores/filters/selectors';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { makeSelectGlobalFilters } from 'ui/containers/HuntApp/stores/global';
import ErrorHandler from 'ui/components/Error';
import { ActionButton } from '../styles';

const ActionsButtons = ({ supportedActions, filterParams, filters, rulesets }) => {
  const [visible, setVisible] = useState(false);
  const [type, setType] = useState(false);
  const [systemSettings, setSystemSettings] = useState([]);
  const rulesList = {
    pagination: {
      page: 1,
      perPage: 10,
      perPageOptions: [10, 20, 50, 100],
    },
    sort: { id: 'created', asc: false },
    view_type: 'list',
  };

  useEffect(() => {
    request(config.API_URL + config.SYSTEM_SETTINGS_PATH).then(systemSettings => {
      setSystemSettings(systemSettings);
    });
  }, []);

  const actions = useMemo(() => {
    const result = [];
    for (let i = 0; i < supportedActions.length; i += 1) {
      const action = supportedActions[i];
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
          systemSettings={systemSettings}
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
  filters: PropTypes.any,
  rulesets: PropTypes.any,
};

const mapStateToProps = createStructuredSelector({
  filterParams: makeSelectFilterParams(),
  filters: makeSelectGlobalFilters(),
  rulesets: filtersSelectors.makeSelectRuleSets(),
});

export default connect(mapStateToProps)(ActionsButtons);
