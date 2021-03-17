import React from 'react';
import styled from 'styled-components';
import { Link } from 'react-router-dom';
import VerticalNavItems from 'hunt_common/components/VerticalNavItems';
import PropTypes from 'prop-types';

const BcStyled = styled.div`
  box-sizing: border-box;
  margin: 0;
  padding: 1px 0px 0px 0px;
  color: rgba(0, 0, 0, 0.65);
  font-variant: tabular-nums;
  line-height: 1.5715;
  list-style: none;
  font-feature-settings: 'tnum';
  color: rgba(0, 0, 0, 0.45);
  font-size: 14px;

  display: flex;
  flex-direction: row;
  height: 100%;
  align-items: stretch;
  margin-left: 20px !important;
`;

const BcItem = styled.div`
  transform: skewX(-15deg);
  display: flex;
  align-items: center;
  padding: 0 10px;
  &:hover {
    background: #144c82;
  }
  &:hover > div {
    opacity: 1;
  }
  &:hover:first-child::before {
    display: block;
    content: '.';
    background: #144c82;
    transform: skewx(15deg);
    height: 100%;
    width: 30px;
    margin-left: -30px;
    position: absolute;
    border-left: 1px solid #08345f;
  }
`;

const StyledLink = styled(Link)`
  color: #fff !important;
  font-size: 16px;
  transform: skewX(15deg);
  &:hover {
    text-decoration: none;
  }
  &:active {
    text-decoration: none;
  }
  &:focus {
    text-decoration: none;
  }
`;

const Separator = styled.div`
  display: flex;
  align-items: center;
  margin: 0 2px;
  cursor: pointer;
  color: #869baf;
  font-size: 20px;
`;

const Breadcrumb = ({ currentPage }) => {
  const { page = '' } = currentPage;
  const navItem = VerticalNavItems.find((p) => p.def === page) || {};
  const { title = '' } = navItem;
  return (
    <BcStyled>
      <React.Fragment>
        <Separator>/</Separator>
        <BcItem>
          <StyledLink to="#">
            <div
              style={{
                fontFamily:
                  "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji'",
              }}
            >
              {process.env.REACT_APP_HAS_TAG === '1' ? (
                <React.Fragment>Scirius Enriched Hunting</React.Fragment>
              ) : (
                <React.Fragment>Suricata Threat Hunting</React.Fragment>
              )}
            </div>
          </StyledLink>
        </BcItem>
      </React.Fragment>
      {title.length > 0 && (
        <React.Fragment>
          <Separator>/</Separator>
          <BcItem>
            <StyledLink to="#">{title}</StyledLink>
          </BcItem>
        </React.Fragment>
      )}
    </BcStyled>
  );
};
Breadcrumb.propTypes = {
  currentPage: PropTypes.object,
};
export default Breadcrumb;
