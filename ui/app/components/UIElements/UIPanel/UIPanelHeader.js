import React from 'react';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const PanelHeaderStyled = styled.div`
  display: grid;
  grid-template-columns: min-content minmax(100px, max-content) 1fr 1fr;
  grid-column-gap: 20px;
  align-items: center;
  width: 100%;
  .sub1 {
    color: #005792;
  }
  .sub3 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(225px, 1fr));
  }
  .sub4 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(215px, 1fr));
    margin-right: 20px;
  }
`;

const UIPanelHeader = ({ sub1, sub2, sub3, sub4 }) => (
  <PanelHeaderStyled>
    {sub1 && <div className="sub1">{sub1}</div>}
    <div>{sub2}</div>
    <div className="sub3">{sub3}</div>
    <div className="sub4">{sub4}</div>
  </PanelHeaderStyled>
);

UIPanelHeader.propTypes = {
  sub1: PropTypes.any,
  sub2: PropTypes.any,
  sub3: PropTypes.any,
  sub4: PropTypes.any,
};

export default UIPanelHeader;
