import React, { useEffect, useState } from 'react';
import { Menu, Popover, Row } from 'antd';
import PropTypes from 'prop-types';
import StamusLogo from 'ui/images/stamus.png';
import { Link } from 'react-router-dom';
import TimeRangePickersContainer from 'ui/components/TimeRangePickersContainer';
import { ClockCircleFilled, ReloadOutlined } from '@ant-design/icons';
import { createStructuredSelector } from 'reselect';
import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import { DATE_TIME_FORMAT } from 'ui/constants';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import { bindActionCreators, compose } from 'redux';
import actions from 'ui/containers/App/actions';
import { connect } from 'react-redux';
import { createGlobalStyle } from 'styled-components';
import ReloadPicker from 'ui/components/ReloadPicker';
import PfIcon from 'ui/components/PfIcon';
import HelpMenu from 'ui/components/HelpMenu';
import UserMenu from 'ui/components/UserMenu';
import selectors from 'ui/containers/App/selectors';
import StyledHeader from './StyledHeader';
import LogoHandler from './LogoHandler';

const iconStyle = {
  fontSize: '20px',
  marginRight: '5px',
};

const GlobalStyle = createGlobalStyle`
  .ant-menu-custom {
    background-color: transparent;
    display: flex;
    justify-content: flex-end;
    align-items: center;
  }
`;

let reloadTimeout = null;

const Header = ({timePicker, setDuration, setTimeSpan, duration, reloadData, doReload, startDate, endDate, menuItems = [] }) => {
  const [hidden, setHidden] = useState(false);
  const [reloadPopOver, setReloadPopOver] = useState(false);
  const [helpPopOver, setHelpPopOver] = useState(false);
  const [userPopOver, setUserPopOver] = useState(false);

  useEffect(() => {
    clearInterval(reloadTimeout);
    if (reloadData.period.seconds > 0) {
      reloadTimeout = setInterval(() => {
        doReload();
      }, reloadData.period.seconds);
    }
  }, [reloadData.period.seconds]);

  const timePreview =
    timePicker === TimePickerEnum.ABSOLUTE
      ? `${startDate.format(DATE_TIME_FORMAT)} - ${endDate.format(DATE_TIME_FORMAT)}`
      : PeriodEnum[duration].title;

  return (
    <StyledHeader>
      <GlobalStyle />
      <LogoHandler>
        <Link to="/appliances/str">
          <img src={StamusLogo} style={{ height: '32px' }} alt="Scirius UI" />
        </Link>
      </LogoHandler>

      <Menu mode='horizontal' theme='custom'>
        <Menu.Item>
          <Popover
            placement="bottom"
            content={<TimeRangePickersContainer setDuration={setDuration} setTimeSpan={setTimeSpan} />}
            trigger="click"
            visible={hidden}
            onVisibleChange={setHidden}
          >
            <Row type="flex" align="middle">
              <ClockCircleFilled style={iconStyle} /> {timePreview}
            </Row>
          </Popover>
        </Menu.Item>
        <Menu.Item style={{ flexShrink: 0 }}>
          <Popover placement="bottomRight" content={<ReloadPicker />} trigger="click" visible={reloadPopOver} onVisibleChange={setReloadPopOver}>
            <Row type="flex" align="middle">
              <ReloadOutlined style={iconStyle} />Reload{' '}
              {reloadData.period.seconds > 0 && <React.Fragment>every {reloadData.period.title}</React.Fragment>}
            </Row>
          </Popover>
        </Menu.Item>
        {/* eslint-disable-next-line react/no-array-index-key */}
        {menuItems.map((menuItem, i) => <Menu.Item key={i}>{menuItem}</Menu.Item>)}
        <Menu.Item>
          <Popover placement="bottomRight" content={<HelpMenu />} trigger="click" visible={helpPopOver} onVisibleChange={setHelpPopOver}>
            <PfIcon type="help" style={iconStyle} />{' '}
          </Popover>
        </Menu.Item>
        <Menu.Item>
          <Popover placement="bottomRight" content={<UserMenu />} trigger="click" visible={userPopOver} onVisibleChange={setUserPopOver}>
            <PfIcon type="user" style={iconStyle} />{' '}
          </Popover>
        </Menu.Item>
      </Menu>
    </StyledHeader>
  );
}

Header.propTypes = {
  timePicker: PropTypes.number,
  setTimeSpan: PropTypes.func,
  setDuration: PropTypes.func,
  duration: PropTypes.any,
  doReload: PropTypes.func,
  reloadData: PropTypes.object,
  menuItems: PropTypes.array,
  startDate: PropTypes.any,
  endDate: PropTypes.any,
}

const mapStateToProps = createStructuredSelector({
  timePicker: selectors.makeSelectTimePicker(),
  duration: selectors.makeSelectDuration(),
  reloadData: selectors.makeSelectReload(),
  startDate: selectors.makeSelectStartDate(),
  endDate: selectors.makeSelectEndDate(),
});

export const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      setDuration: actions.setDuration,
      setTimeSpan: actions.setTimeSpan,
      doReload: actions.doReload,
    },
    dispatch,
  );

const withConnect = connect(
  mapStateToProps,
  mapDispatchToProps,
);

export default compose(withConnect)(Header);
