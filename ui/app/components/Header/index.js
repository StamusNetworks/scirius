import React, { useState } from 'react';

import { ClockCircleOutlined, QuestionCircleOutlined, UserOutlined, ReloadOutlined } from '@ant-design/icons';
import { Menu, Popover, Tooltip } from 'antd';
import { observer } from 'mobx-react-lite';
// icon select: https://fonts.google.com/icons?selected=Material+Icons
// React name for icon: select checkbox, click the icon and see the name for the import: https://mui.com/components/material-icons
import moment from 'moment';
import PropTypes from 'prop-types';
import { useDispatch } from 'react-redux';

import HelpMenu from 'ui/components/HelpMenu';
import TimeRangePickersContainer from 'ui/components/TimeRangePickersContainer';
import UserMenu from 'ui/components/UserMenu';
import constants from 'ui/constants';
import actions from 'ui/containers/App/actions';
import StamusLogo from 'ui/images/stamus.png';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import { useStore } from 'ui/mobx/RootStoreProvider';

import { HeaderStyled, Logo, RangePreview, ReloadButton } from './styles';

const { DATE_TIME_FORMAT } = constants;

const Header = ({ menuItems = [] }) => {
  const [helpPopOver, setHelpPopOver] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [userPopOver, setUserPopOver] = useState(false);
  const { commonStore } = useStore();
  const dispatch = useDispatch();

  return (
    <HeaderStyled>
      <Logo to="/stamus">
        <img src={StamusLogo} alt="Scirius UI" />
      </Logo>

      <Menu theme="dark" mode="horizontal">
        <Menu.Item key="reload">
          <Tooltip title="Reload now">
            <ReloadButton
              onClick={() => {
                dispatch(actions.doReload());
                commonStore.reload();
              }}
              icon={<ReloadOutlined />}
              type="ghost"
            >
              Reload
            </ReloadButton>
          </Tooltip>
        </Menu.Item>
        {menuItems.map(menuItem => (
          <Menu.Item key={menuItem.key} className="tenant-dropdown">
            {menuItem.content}
          </Menu.Item>
        ))}
        <Menu.Item key="timerange-dropdown" className="timerange-dropdown" data-test="timerange-dropdown">
          <Popover placement="bottomRight" content={<TimeRangePickersContainer />} trigger="click" visible={hidden} onVisibleChange={setHidden}>
            {commonStore.timeRangeType === 'relative' && (
              <React.Fragment>
                <ClockCircleOutlined /> {PeriodEnum[commonStore.relativeType].title}
              </React.Fragment>
            )}
            {commonStore.timeRangeType === 'absolute' && (
              <Tooltip
                placement="bottom"
                title={
                  <RangePreview>
                    <tr>
                      <td className="col">From</td>
                      <td>{moment(commonStore.startDate * 1000).format(DATE_TIME_FORMAT)}</td>
                    </tr>
                    <tr>
                      <td className="col">To</td>
                      <td>{moment(commonStore.endDate * 1000).format(DATE_TIME_FORMAT)}</td>
                    </tr>
                  </RangePreview>
                }
              >
                <ClockCircleOutlined /> {moment(commonStore.startDate * 1000).format(DATE_TIME_FORMAT)} -{' '}
                {moment(commonStore.endDate * 1000).format(DATE_TIME_FORMAT)}
              </Tooltip>
            )}
          </Popover>
        </Menu.Item>
        <Menu.Item key="help" className="help-dropdown">
          <Popover placement="bottomRight" content={<HelpMenu />} trigger="click" visible={helpPopOver} onVisibleChange={setHelpPopOver}>
            <QuestionCircleOutlined /> Help
          </Popover>
        </Menu.Item>
        {commonStore.user && (
          <Menu.Item data-test="username-link" key="user-dropdown" className="user-dropdown" style={{ height: '100%' }}>
            <Popover placement="bottomRight" content={<UserMenu />} trigger="click" visible={userPopOver} onVisibleChange={setUserPopOver}>
              <span>
                <UserOutlined /> {commonStore.user.username}
              </span>
            </Popover>
          </Menu.Item>
        )}
      </Menu>
    </HeaderStyled>
  );
};

Header.propTypes = {
  menuItems: PropTypes.array, // not required! only used by EE
};

export default observer(Header);
