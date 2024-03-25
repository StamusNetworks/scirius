import React from 'react';

import PropTypes from 'prop-types';

const AntdIcon = ({ component }) => {
  const Component = component;
  return (
    <span role="img" className="anticon">
      <Component />
    </span>
  );
};

AntdIcon.propTypes = {
  component: PropTypes.any,
};

export default AntdIcon;
