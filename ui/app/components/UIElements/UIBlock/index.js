import React from 'react';
import PropTypes from 'prop-types';

const UIBlock = ({ title, description, style, children }) => (
    <div style={(style || {})}>
      {title && <h2>{title}</h2>}
      {description && <p>{description}</p>}
      {children}
    </div>
  )

UIBlock.propTypes = {
  title: PropTypes.string,
  description: PropTypes.string,
  style: PropTypes.object,
  children: PropTypes.any,
}

export default UIBlock;
