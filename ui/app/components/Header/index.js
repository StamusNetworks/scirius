import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { connect } from 'react-redux';
import { bindActionCreators, compose } from 'redux';
import PropTypes from 'prop-types';
import { Layout, Menu, Popover, Progress } from 'antd';
import styled from 'styled-components';
import { ClockCircleOutlined, ReloadOutlined } from '@ant-design/icons';
import selectors from 'ui/containers/App/selectors';
import { createStructuredSelector } from 'reselect';
import AccountCircleRounded from "@material-ui/icons/AccountCircleRounded";
// icon select: https://fonts.google.com/icons?selected=Material+Icons
// React name for icon: select checkbox, click the icon and see the name for the import: https://mui.com/components/material-icons

import './style.scss';
import StamusLogo from 'ui/images/stamus.png';
import SwitchApps from 'ui/components/SwitchApps';
import TimeRangePickersContainer from 'ui/components/TimeRangePickersContainer';
import HelpMenu from 'ui/components/HelpMenu';
import UserMenu from 'ui/components/UserMenu';
import { COLOR_ANT_MENU, COLOR_BRAND_BLUE, COLOR_ANT_MENU_FONT_HOVER } from 'ui/constants/colors';
import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import constants from 'ui/constants';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import actions from 'ui/containers/App/actions';
import ReloadPicker from 'ui/components/ReloadPicker';

const { DATE_TIME_FORMAT } = constants;
const { Header: AntdHeader } = Layout;
let reloadTimeout = null;
let animateTimeout = null;

const ProgressStyled = styled(Progress)`
  line-height: 1em;
  .ant-progress-inner {
    width: 14px !important;
    height: 14px !important;
    vertical-align: top;
  }
`

const Header = ({ duration, endDate, setDuration, setTimeSpan, startDate, timePicker, doReload, reloadData, menuItems = [] }) => {
  const [helpPopOver, setHelpPopOver] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [userPopOver, setUserPopOver] = useState(false);
  const [reloadPopOver, setReloadPopOver] = useState(false);
  const [progress, setProgress] = useState(0);

  const timePreview =
    timePicker === TimePickerEnum.ABSOLUTE
      ? `${startDate.format(DATE_TIME_FORMAT)} - ${endDate.format(DATE_TIME_FORMAT)}`
      : PeriodEnum[duration].title;

  const decrease = useCallback((seconds) => {
    animateTimeout = setTimeout(() => {
      const v = seconds - 1000;
      setProgress(v);
      if (v > 0) {
        decrease(v);
      }
    }, 1000);
  }, [progress]);

  useEffect(() => {
    clearInterval(reloadTimeout);
    clearInterval(animateTimeout);
    if (reloadData.period.seconds > 0) {
      decrease(reloadData.period.seconds);
      reloadTimeout = setInterval(() => {
        doReload();
        decrease(reloadData.period.seconds);
      }, reloadData.period.seconds);
    }
  }, [reloadData.period.seconds]);

  return (
    <AntdHeader className="header" style={{ background: COLOR_ANT_MENU }}>
      <Link to="/stamus" className="logo">
        <img src={StamusLogo} alt="Scirius UI" />
      </Link>

      <Menu theme="dark" mode="horizontal">
        {menuItems.map((menuItem) => (<Menu.Item key={menuItem.key} className="tenant-dropdown">{menuItem.content}</Menu.Item>))}
        <Menu.Item key="timerange-dropdown" className="timerange-dropdown" data-test="timerange-dropdown">
          <Popover
            placement="bottom"
            content={<TimeRangePickersContainer setDuration={setDuration} setTimeSpan={setTimeSpan} />}
            trigger="click"
            visible={hidden}
            onVisibleChange={setHidden}
          >
            <ClockCircleOutlined /> {timePreview}
          </Popover>
        </Menu.Item>
        <Menu.Item key="reload" className="reload-dropdown">
          <Popover placement="bottomRight" content={<ReloadPicker />} trigger="click" visible={reloadPopOver} onVisibleChange={setReloadPopOver}>
            {reloadData.period.seconds > 0 && (<ProgressStyled type="circle" width={14} strokeColor={COLOR_BRAND_BLUE} trailColor={COLOR_ANT_MENU_FONT_HOVER} percent={100-(progress/reloadData.period.seconds*100)} strokeWidth={8} showInfo={false} />)}
            {reloadData.period.seconds === 0 && (<ReloadOutlined style={{ fontSize: '14px ' }} />)} Reload
            {reloadData.period.seconds > 0 && (<React.Fragment> every {reloadData.period.title}</React.Fragment>)}
          </Popover>
        </Menu.Item>
        <Menu.Item key="apps">
          <Popover placement="bottomRight" content={<SwitchApps />} trigger="click">
            Apps
          </Popover>
        </Menu.Item>
        <Menu.Item key="help">
          <Popover placement="bottomRight" content={<HelpMenu />} trigger="click" visible={helpPopOver} onVisibleChange={setHelpPopOver}>
            Help
          </Popover>
        </Menu.Item>
        <Menu.Item key="user-dropdown" className="user-dropdown" style={{ height: '100%' }}>
          <Popover placement="bottomRight" content={<UserMenu />} trigger="click" visible={userPopOver} onVisibleChange={setUserPopOver}>
            <span>
              <AccountCircleRounded style={{color: "currentColor", strokeWidth: 1.5 }} />
            </span>
          </Popover>
        </Menu.Item>
      </Menu>
    </AntdHeader>
  );
};

Header.propTypes = {
  duration: PropTypes.oneOf(Object.keys(PeriodEnum)).isRequired,
  endDate: PropTypes.object,
  setTimeSpan: PropTypes.func.isRequired,
  setDuration: PropTypes.func.isRequired,
  startDate: PropTypes.object,
  timePicker: PropTypes.oneOf([0, 1]).isRequired,
  reloadData: PropTypes.object,
  doReload: PropTypes.func,
  menuItems: PropTypes.array // not required! only used by EE
};

const mapStateToProps = createStructuredSelector({
  timePicker: selectors.makeSelectTimePicker(),
  duration: selectors.makeSelectDuration(),
  startDate: selectors.makeSelectStartDate(),
  endDate: selectors.makeSelectEndDate(),
  reloadData: selectors.makeSelectReload(),
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
