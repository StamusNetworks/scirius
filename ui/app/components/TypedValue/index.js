import React from 'react';
import PropTypes from 'prop-types';

import { Dropdown, message } from 'antd';
import { CopyOutlined, IdcardOutlined, InfoCircleFilled, RobotOutlined, UserOutlined, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import _ from 'lodash';
import styled from 'styled-components';
import { Link } from 'ui/helpers/Link';
import history from 'ui/utils/history';
import copyTextToClipboard from 'ui/helpers/copyTextToClipboard';
import isIP from 'ui/helpers/isIP';
import { useStore } from 'ui/mobx/RootStoreProvider';

const Value = styled.a`
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const rolesMap = {
  'Domain Controller': {
    label: 'Domain controller',
    value: 'domain controller',
  },
  'DHCP Server': {
    label: 'DHCP',
    value: 'dhcp',
  },
  'HTTP(s) Proxy': {
    label: 'HTTP(S) proxy',
    value: 'http proxy',
  },
  Printer: {
    label: 'Printer',
    value: 'printer',
  },
  Unclassified: {
    label: 'Unclassified',
    value: 'unclassified',
  },
};

const TypedValue = ({ additionalLinks, printedValue, redirect, value, type }) => {
  const { commonStore } = useStore();
  const virusTotalLink = (
    <a href={`https://www.virustotal.com/gui/${isIP(encodeURIComponent(value)) ? 'ip-address' : 'domain'}/${value}`} target="_blank">
      <InfoCircleFilled /> <span>External info</span>
    </a>
  );

  let listOfLinks = [
    {
      key: 'copyTextToClipboard',
      label: (
        <div
          onClick={e => {
            e.stopPropagation();
            copyTextToClipboard(printedValue || value);
            message.success({
              duration: 1,
              content: 'Copied!',
            });
          }}
        >
          <CopyOutlined /> <span>Copy text to clipboard</span>
        </div>
      ),
    },
  ];

  const getRoleLabel = (location, removeFilters = false) => (
    <div
      onClick={e => {
        e.stopPropagation();
        if (removeFilters) commonStore.clearFilters();
        commonStore.addFilter({
          id: 'host_id.roles.name',
          value: rolesMap[value.props.name].value || '',
          label: `Hosts: Roles: ${rolesMap[value.props.name].label}`,
          fullString: false,
          negated: false,
          query: 'filter_host_id',
        });
        if (redirect) history.push(`/stamus/hunting/${location}${window.location.search}`);
      }}
    >
      <RobotOutlined /> <span>Filter on Role, go to {_.capitalize(location)}</span>
    </div>
  );

  if (type === 'role') {
    listOfLinks = [
      {
        key: 'typedValueRole1',
        label: getRoleLabel('hosts'),
      },
      {
        key: 'typedValueRole2',
        label: getRoleLabel('dashboards', true),
      },
      {
        key: 'typedValueRole3',
        label: getRoleLabel('events'),
      },
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (type === 'ip') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValueIP1',
        label: (
          <Link to={`/stamus/hunting/hosts/host-insight/${value}`}>
            <div>
              <IdcardOutlined /> <span>Open Host Insight page for IP</span>
            </div>
          </Link>
        ),
      },
      {
        key: 'typedValueIP2',
        label: (
          <div
            onClick={e => {
              e.stopPropagation();
              commonStore.addFilter({
                id: 'ip',
                value: value || '',
                label: `IP: ${value}`,
                fullString: false,
                negated: false,
                query: 'filter',
              });
              if (redirect) history.push('/stamus/hunting/dashboards');
            }}
          >
            <ZoomInOutlined /> <span>Filter on IP: {value}</span>
          </div>
        ),
      },
      {
        key: 'typedValueIP3',
        label: (
          <div
            onClick={e => {
              e.stopPropagation();
              commonStore.addFilter({
                id: 'ip',
                value: value || '',
                label: `IP: ${value}`,
                fullString: false,
                negated: true,
                query: 'filter',
              });
              if (redirect) history.push('/stamus/hunting/dashboards');
            }}
          >
            <ZoomOutOutlined /> <span>Negated filter on IP: {value}</span>
          </div>
        ),
      },
      {
        key: 'typedValueIP4',
        label: virusTotalLink,
      },
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (type === 'port') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValuePort',
        label: (
          <a href={`https://www.dshield.org/port.html?port=${value}`} target="_blank">
            <div>
              <InfoCircleFilled /> <span>External info</span>
            </div>
          </a>
        ),
      },
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (type === 'hostname') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValueHostname',
        label: virusTotalLink,
      },
    ].filter(obj => !_.isEmpty(obj.label));
  }

  if (type === 'username') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValueUsername',
        label: (
          <div
            onClick={e => {
              e.stopPropagation();
              commonStore.addFilter({
                id: 'host_id.username.user',
                value: value || '',
                label: `host_id.username.user: ${value}`,
                fullString: false,
                negated: false,
              });
            }}
          >
            <UserOutlined /> <span>Filter on username</span>
          </div>
        ),
      },
    ].filter(obj => !_.isEmpty(obj.label));
  }

  if (type === 'networkInfo') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValueNetInfo',
        label: (
          <div
            onClick={e => {
              e.stopPropagation();
              commonStore.addFilter({
                id: 'host_id.net_info.agg',
                value: value || '',
                label: `host_id.net_info.agg: ${value}`,
                fullString: false,
                negated: false,
              });
            }}
          >
            <UserOutlined /> <span>Filter on Net Info</span>
          </div>
        ),
      },
      {
        key: 'typedValueNetInfoNegated',
        label: (
          <div
            onClick={e => {
              e.stopPropagation();
              commonStore.addFilter({
                id: 'host_id.net_info.agg',
                value: value || '',
                label: `host_id.net_info.agg: ${value}`,
                fullString: false,
                negated: true,
              });
            }}
          >
            <UserOutlined /> <span>Negated filter on Net Info</span>
          </div>
        ),
      },
    ].filter(obj => !_.isEmpty(obj.label));
  }

  if (type !== 'ip' && type !== 'port' && type !== 'username' && type !== 'hostname') {
    listOfLinks = [...additionalLinks, ...listOfLinks].filter(obj => !_.isEmpty(obj.label));
  }

  return (
    <Dropdown
      menu={{
        items: [
          {
            type: 'group', // Must have
            label: printedValue || value,
            children: listOfLinks,
          },
        ],
      }}
      trigger={['click']}
      destroyPopupOnHide // necessary for the tests! makes sure only one +/- magnifier exists at any time
      onClick={e => e.stopPropagation()}
    >
      <Value data-test={printedValue || value}>{printedValue || value}</Value>
    </Dropdown>
  );
};

TypedValue.defaultProps = {
  additionalLinks: [],
};

TypedValue.propTypes = {
  type: PropTypes.string.isRequired, // 'ip|hostname|username|port'
  value: PropTypes.any.isRequired,
  redirect: PropTypes.bool,
  additionalLinks: PropTypes.arrayOf(PropTypes.object),
  printedValue: PropTypes.any,
};

export default TypedValue;
