import React from 'react';
import PropTypes from 'prop-types';
import { DropdownKebab, MenuItem } from 'patternfly-react';
import RuleToggleModal from 'hunt_common/RuleToggleModal';
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

    render() {
        return (
            <React.Fragment>
                <DropdownKebab id="ruleActions" pullRight>
                    <MenuItem onClick={() => { this.displayToggle('enable'); }}>Enable Rule</MenuItem>
                    <MenuItem onClick={() => { this.displayToggle('disable'); }}>Disable Rule</MenuItem>
                    <MenuItem divider />
                    <MenuItem href={`/rules/rule/pk/${this.props.config.rule.pk}/`}>Rule page in Scirius</MenuItem>
                </DropdownKebab>
                <ErrorHandler>
                    {this.state.toggle.show && <RuleToggleModal
                        show={this.state.toggle.show}
                        action={this.state.toggle.action}
                        config={this.props.config}
                        close={this.hideToggle}
                        rulesets={this.props.rulesets}
                        refresh_callback={this.props.refresh_callback}
                    />}
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
