import React from 'react';
import PropTypes from 'prop-types';
import styled from 'styled-components';
import { BugOutlined } from '@ant-design/icons';

const ErrorMessage = styled.h3`
  width: 100%;
  display: grid;
  align-content: center;
  justify-items: center;
  grid-row-gap: 10px;

  span {
    font-size: 27px;
    color: #005792;
  }

  div:first-of-type {
    text-transform: uppercase;
    font-weight: bold;
    color: #005792;
  }

  div:last-of-type {
    font-weight: normal;
  }
`;

class ErrorHandler extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  componentDidCatch() {
    this.setState({ hasError: true });
  }

  componentDidUpdate(prevProps, prevState) {
    if (prevState.hasError === true) {
      // eslint-disable-next-line react/no-did-update-set-state
      this.setState({
        hasError: false,
      });
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <ErrorMessage>
          <BugOutlined />
          <div>Something went wrong. </div>
          <div>Please reload the page, it may fix the issue.</div>
        </ErrorMessage>
      );
    }
    return this.props.children;
  }
}

ErrorHandler.propTypes = {
  children: PropTypes.any,
};

export default ErrorHandler;
