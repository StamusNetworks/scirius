import React from 'react';
import PropTypes from 'prop-types';
import {
  CloseCircleOutlined,
  DoubleRightOutlined,
  MinusCircleOutlined,
  PoweroffOutlined,
  SelectOutlined,
  TableOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';
import RuleContentModal from 'ui/components/RuleContentModal';
import UICard from 'ui/components/UIElements/UICard';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';
import styled from 'styled-components';

const UICardBody = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  padding: 8px 10px;
`;

export default class RuleStatus extends React.Component {
  constructor(props) {
    super(props);

    this.state = { display_content: false };
  }

  showRuleContent = () => {
    this.setState({ display_content: true });
  };

  hideRuleContent = () => {
    this.setState({ display_content: false });
  };

  render() {
    const { valid } = this.props.rule_status;
    let validity = (
      <div>
        <CheckCircleOutlined style={{ color: COLOR_BRAND_BLUE, marginRight: '3px' }} />
        Valid
      </div>
    );
    if (valid.status !== true) {
      validity = (
        <div>
          <CloseCircleOutlined style={{ color: COLOR_BRAND_BLUE, marginRight: '3px' }} />
          Invalid
        </div>
      );
    }
    const trans = this.props.rule_status.transformations;
    let action = (
      <div>
        <CheckCircleOutlined style={{ color: COLOR_BRAND_BLUE, marginRight: '3px' }} />
        <span>Action: {trans.action}</span>
      </div>
    );
    if (trans.action === null) {
      action = undefined;
    }
    let target = (
      <div>
        <SelectOutlined style={{ color: COLOR_BRAND_BLUE, marginRight: '3px' }} />
        <span>Target: {trans.target}</span>
      </div>
    );
    if (trans.target == null) {
      target = undefined;
    }
    let lateral = (
      <div>
        <DoubleRightOutlined style={{ color: COLOR_BRAND_BLUE, marginRight: '3px' }} />
        <span>Lateral: {trans.lateral}</span>
      </div>
    );
    if (trans.lateral == null) {
      lateral = undefined;
    }
    let active = (
      <div>
        <PoweroffOutlined style={{ color: COLOR_BRAND_BLUE, marginRight: '3px' }} />
        Active
      </div>
    );
    if (!this.props.rule_status.active) {
      active = (
        <div>
          <MinusCircleOutlined style={{ transform: 'rotateZ(90deg)', color: COLOR_BRAND_BLUE, marginRight: '3px' }} />
          Disabled
        </div>
      );
    }

    return (
      <React.Fragment>
        <UICard
          title={
            <div>
              <TableOutlined style={{ color: COLOR_BRAND_BLUE, marginRight: '10px' }} />
              <span>{this.props.rule_status.name}</span>
            </div>
          }
          onClick={this.showRuleContent}
          style={{ cursor: 'pointer' }}
          headStyle={{ color: COLOR_BRAND_BLUE, textAlign: 'center' }}
          noPadding
        >
          <UICardBody>
            {active}
            {validity}
            {action}
            {target}
            {lateral}
          </UICardBody>
        </UICard>

        <RuleContentModal
          display={this.state.display_content}
          rule={this.props.rule}
          close={this.hideRuleContent}
          rule_status={this.props.rule_status}
        />
      </React.Fragment>
    );
  }
}
RuleStatus.propTypes = {
  rule_status: PropTypes.any,
  rule: PropTypes.any,
};
