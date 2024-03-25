import React, { Component } from 'react';

import PropTypes from 'prop-types';

export default class ErrorHandler extends Component {
  constructor(props) {
    super(props);
    this.state = {
      error: null,
      errorInfo: null,
    };
  }

  componentDidCatch(err, errInfo) {
    if (err) {
      // eslint-disable-next-line no-console
      console.error('Error: ', err);
    }
    if (errInfo) {
      // eslint-disable-next-line no-console
      console.error('ErrorInfo: ', errInfo.componentStack);
    }
    this.setState({ error: err, errorInfo: errInfo });
  }

  render() {
    if (this.state.errorInfo) {
      return (
        <div>
          {/* <h2>Something went wrong ! </h2> */}
          <p>{this.state.error && this.state.error.toString()}</p>
          <details style={{ whiteSpace: 'pre-wrap' }}>
            <pre>{this.state.errorInfo.componentStack}</pre>
          </details>
        </div>
      );
    }
    return this.props.children;
  }
}

ErrorHandler.propTypes = {
  children: PropTypes.any,
};
