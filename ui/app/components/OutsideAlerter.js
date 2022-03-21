import React, { Component } from 'react';
import PropTypes from 'prop-types';

class OutsideAlerter extends Component {
  constructor(props) {
    super(props);

    this.setWrapperRef = this.setWrapperRef.bind(this);
    this.handleClickOutside = this.handleClickOutside.bind(this);
  }

  componentDidMount() {
    document.addEventListener('mousedown', this.handleClickOutside);
  }

  componentWillUnmount() {
    document.removeEventListener('mousedown', this.handleClickOutside);
  }

  setWrapperRef(node) {
    this.wrapperRef = node;
  }

  handleClickOutside(event) {
    if (this.wrapperRef && !this.wrapperRef.contains(event.target)) {
      this.props.hide();
    }
  }

  render() {
    return <span ref={this.setWrapperRef}>{this.props.children}</span>;
  }
}

OutsideAlerter.propTypes = {
  hide: PropTypes.func,
  children: PropTypes.element.isRequired,
};

export default OutsideAlerter;
