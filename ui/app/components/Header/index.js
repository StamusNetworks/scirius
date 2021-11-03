import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { connect } from 'react-redux';
import { bindActionCreators, compose } from 'redux';
import PropTypes from 'prop-types';
import { Layout, Menu, Popover } from 'antd';
import { ClockCircleOutlined } from '@ant-design/icons';
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
import { COLOR_ANT_MENU } from 'ui/constants/colors';
import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import constants from 'ui/constants';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import actions from 'ui/containers/App/actions';

const { DATE_TIME_FORMAT } = constants;
const { Header: AntdHeader } = Layout;

const Header = ({ duration, endDate, setDuration, setTimeSpan, startDate, timePicker, menuItems = [] }) => {
  const [helpPopOver, setHelpPopOver] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [userPopOver, setUserPopOver] = useState(false);

  const timePreview =
    timePicker === TimePickerEnum.ABSOLUTE
      ? `${startDate.format(DATE_TIME_FORMAT)} - ${endDate.format(DATE_TIME_FORMAT)}`
      : PeriodEnum[duration].title;

  return (
    <AntdHeader className="header" style={{ background: COLOR_ANT_MENU }}>
      <Link to="/stamus" className="logo">
        <img src={StamusLogo} alt="Scirius UI" />
      </Link>

      <Menu theme="dark" mode="horizontal">
        {menuItems.map((menuItem) => (<React.Fragment key={menuItem}>{menuItem}</React.Fragment>))}
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
        <Menu.Item key="user-dropdown" className="user-dropdown">
          <Popover placement="bottomRight" content={<UserMenu />} trigger="click" visible={userPopOver} onVisibleChange={setUserPopOver}>
            <AccountCircleRounded style={{color: "currentColor", strokeWidth: 1.5}} />
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
  menuItems: PropTypes.array // not required! only used by EE
};

const mapStateToProps = createStructuredSelector({
  timePicker: selectors.makeSelectTimePicker(),
  duration: selectors.makeSelectDuration(),
  startDate: selectors.makeSelectStartDate(),
  endDate: selectors.makeSelectEndDate(),
});

export const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      setDuration: actions.setDuration,
      setTimeSpan: actions.setTimeSpan,
    },
    dispatch,
  );

const withConnect = connect(
  mapStateToProps,
  mapDispatchToProps,
);

export default compose(withConnect)(Header);
