import React from 'react';

import { Button } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const ButtonStyled = styled(Button)`
  height: 22px;
  width: 22px;
  border-radius: 0;
  transition: none;
  &:hover {
    background: ${p => p?.color || 'none'};
  }
`;

const FilterButton = ({ onClick, icon, color, ...props }) => {
  const Icon = icon ? React.cloneElement(icon, { style: { color: '#FFF', fontSize: 12 } }) : null;
  return <ButtonStyled {...props} color={color} type="link" icon={Icon} onClick={onClick} />;
};

export default FilterButton;

FilterButton.propTypes = {
  icon: PropTypes.func.isRequired,
  onClick: PropTypes.func,
  color: PropTypes.func,
};
