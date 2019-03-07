import React from 'react';
import PropTypes from 'prop-types';
import { DropdownKebab, MenuItem } from 'patternfly-react';
import FilterToggleModal from '../FilterToggleModal';
import ErrorHandler from './Error';

export default class FilterEditKebab extends React.Component {
    constructor(props) {
        super(props);
        this.displayToggle = this.displayToggle.bind(this);
        this.hideToggle = this.hideToggle.bind(this);
        this.state = { toggle: { show: false, action: 'delete' } };
        this.closeAction = this.closeAction.bind(this);
    }

    displayToggle(action) {
        this.setState({ toggle: { show: true, action } });
    }

    hideToggle() {
        this.setState({ toggle: { show: false, action: this.state.toggle.action } });
    }

    closeAction() {
        this.setState({ toggle: { show: false, action: 'delete' } });
    }

    render() {
        return (
            <React.Fragment>
                <DropdownKebab id="filterActions" pullRight>
                    {this.props.data.index !== 0 && <MenuItem onClick={() => { this.displayToggle('movetop'); }}>
                        Send Filter to top
                    </MenuItem>}
                    <MenuItem onClick={() => { this.displayToggle('move'); }}>
                        Move Filter
                    </MenuItem>
                    <MenuItem onClick={() => { this.displayToggle('movebottom'); }}>
                        Send Filter to bottom
                    </MenuItem>
                    <MenuItem divider />
                    <MenuItem onClick={() => { this.displayToggle('delete'); }}>
                        Delete Filter
                    </MenuItem>
                </DropdownKebab>
                <ErrorHandler>
                    <FilterToggleModal show={this.state.toggle.show} action={this.state.toggle.action} data={this.props.data} close={this.closeAction} last_index={this.props.last_index} needUpdate={this.props.needUpdate} />
                </ErrorHandler>
            </React.Fragment>
        );
    }
}
FilterEditKebab.propTypes = {
    data: PropTypes.any,
    last_index: PropTypes.any,
    needUpdate: PropTypes.any,
};
