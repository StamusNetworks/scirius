import React, { Component } from 'react';
import PropTypes from 'prop-types';

export default class ExternalLink extends Component {
    constructor(props) {
        super(props);
        this.state = {
            onclick: props.onClick,
            icon: props.icon,
            title: props.title,
            tooltip: props.tooltip
        };
    }

    render() {
        return (
            <li className="applauncher-pf-item" role="presentation">
                <a className="applauncher-pf-link" onClick={this.state.onclick} role="menuitem" data-toggle="tooltip" title={this.state.tooltip} style={{ cursor: 'pointer' }}>
                    <i className={this.state.icon} aria-hidden="true"></i>
                    <span className="applauncher-pf-link-title">{this.state.title}</span>
                </a>
            </li>
        );
    }
}
ExternalLink.propTypes = {
    onClick: PropTypes.any,
    icon: PropTypes.any,
    title: PropTypes.any,
    tooltip: PropTypes.any,
};
