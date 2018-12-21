import React from 'react';
import PropTypes from 'prop-types';
import RuleContentModal from './components/RuleContentModal';

export default class RuleStatus extends React.Component {
    constructor(props) {
        super(props);

        this.state = { display_content: false };
    }

    showRuleContent = () => {
        this.setState({ display_content: true });
    }

    hideRuleContent = () => {
        this.setState({ display_content: false });
    }

    render() {
        const { valid } = this.props.rule_status;
        let validity = <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-ok"></span>Valid</span>;
        if (valid.status !== true) {
            validity = <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-error-circle-o"></span>Valid</span>;
        }
        const trans = this.props.rule_status.transformations;
        let action = <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-ok" title="Action transformation"></span>Action: {trans.action}</span>;
        if (trans.action === null) {
            action = undefined;
        }
        let target = <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-import" title="Target transformation"></span>Target: {trans.target}</span>;
        if (trans.target == null) {
            target = undefined;
        }
        let lateral = <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-integration" title="Lateral transformation"></span>Lateral: {trans.lateral}</span>;
        if (trans.lateral == null) {
            lateral = undefined;
        }
        let active = <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-on"></span>Active</span>;
        if (!this.props.rule_status.active) {
            active = <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-off"></span>Disabled</span>;
        }

        return (
            <div className="col-xs-6 col-sm-4 col-md-4">
                {/* eslint-disable-next-line jsx-a11y/no-static-element-interactions, jsx-a11y/click-events-have-key-events */}
                <div className="card-pf card-pf-accented card-pf-aggregate-status" onClick={this.showRuleContent} style={{ cursor: 'pointer' }}>
                    <h2 className="card-pf-title">
                        <span className="fa fa-shield" />{this.props.rule_status.name}
                    </h2>
                    <div className="card-pf-body">
                        <p className="card-pf-aggregate-status-notifications">
                            {active}
                            {validity}
                            {action}
                            {target}
                            {lateral}
                        </p>
                    </div>
                </div>

                <RuleContentModal display={this.state.display_content} rule={this.props.rule} close={this.hideRuleContent} rule_status={this.props.rule_status} />
            </div>
        );
    }
}
RuleStatus.propTypes = {
    rule_status: PropTypes.any,
    rule: PropTypes.any,
};
