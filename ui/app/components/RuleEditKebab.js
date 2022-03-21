import React from 'react';
import PropTypes from 'prop-types';
import { Dropdown, Menu } from 'antd';
import { MenuOutlined } from '@ant-design/icons';
import RuleToggleModal from 'hunt_common/RuleToggleModal';
import { APP_NAME_SHORT } from 'hunt_common/constants';
import ErrorHandler from './Error';

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
    this.setState({ toggle: { show: false, action: this.state.toggle.action } });
  }

  menu = (
    <Menu>
      <Menu.Item
        key="enable"
        onClick={() => {
          this.displayToggle('enable');
        }}
      >
        {' '}
        Enable Rule{' '}
      </Menu.Item>
      <Menu.Item
        key="disable"
        onClick={() => {
          this.displayToggle('disable');
        }}
      >
        {' '}
        Disable Rule{' '}
      </Menu.Item>
      <Menu.Item key="rpis">
        <a href={`/rules/rule/pk/${this.props.config.rule.pk}/`}> Rule page in {APP_NAME_SHORT} </a>
      </Menu.Item>
    </Menu>
  );

  render() {
    return (
      <React.Fragment>
        <Dropdown id="ruleActions" overlay={this.menu} trigger={['click']}>
          <a className="ant-dropdown-link" onClick={(e) => e.preventDefault()}>
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
