import React from 'react';

import { MenuOutlined } from '@ant-design/icons';
import { Dropdown, Menu } from 'antd';
import PropTypes from 'prop-types';

import RuleToggleModal from 'RuleToggleModal';
import ErrorHandler from 'ui/components/Error';
import { APP_NAME_SHORT } from 'ui/constants';

export default class RuleEditKebab extends React.Component {
  constructor(props) {
    super(props);
    this.state = { toggle: { show: false, action: 'Disable' } };
    this.displayToggle = this.displayToggle.bind(this);
    this.hideToggle = this.hideToggle.bind(this);
  }

  displayToggle(action) {
    this.setState({ toggle: { show: true, action } });
  }

  hideToggle() {
    // eslint-disable-next-line react/no-access-state-in-setstate
    this.setState({ toggle: { show: false, action: this.state.toggle.action } });
  }

  menu = (
    // eslint-disable-next-line no-unused-vars
    <Menu onClick={({ item, key, keyPath, domEvent }) => domEvent.stopPropagation()}>
      <Menu.Item
        key="enable"
        onClick={() => {
          this.displayToggle('enable');
        }}
        data-test="enable-rule"
      >
        {' '}
        Enable Rule{' '}
      </Menu.Item>
      <Menu.Item
        key="disable"
        onClick={() => {
          this.displayToggle('disable');
        }}
        data-test="disable-rule"
      >
        {' '}
        Disable Rule{' '}
      </Menu.Item>
      <Menu.Item key="rpis" data-test="rule-page-in-scs">
        <a href={`/rules/rule/pk/${this.props.config.rule.pk}/`}> Rule page in {APP_NAME_SHORT} </a>
      </Menu.Item>
    </Menu>
  );

  render() {
    return (
      <React.Fragment>
        <Dropdown id="ruleActions" overlay={this.menu} trigger={['click']}>
          <a
            className="ant-dropdown-link"
            onClick={e => {
              e.preventDefault();
              e.stopPropagation();
            }}
            data-test="rule-edit-kebab-menu"
          >
            <MenuOutlined />
          </a>
        </Dropdown>
        <ErrorHandler>
          {this.state.toggle.show && (
            <RuleToggleModal
              show={this.state.toggle.show}
              action={this.state.toggle.action}
              config={this.props.config}
              close={this.hideToggle}
              rulesets={this.props.rulesets}
              refresh_callback={this.props.refresh_callback}
            />
          )}
        </ErrorHandler>
      </React.Fragment>
    );
  }
}
RuleEditKebab.propTypes = {
  config: PropTypes.any,
  rulesets: PropTypes.any,
  refresh_callback: PropTypes.any,
};
