import React from 'react';
import PropTypes from 'prop-types';
import { BugOutlined } from '@ant-design/icons';
import { Typography } from 'antd';
const { Title } = Typography;

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
        <React.Fragment>
          <Title level={4}>
            <BugOutlined /> Oops! Something went wrong.
          </Title>
          Please reload the page, it may fix the issue.
        </React.Fragment>
      );
    }
    return this.props.children;
  }
}

ErrorHandler.propTypes = {
  children: PropTypes.any,
};

export default ErrorHandler;
