import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Dropdown, message } from 'antd';
import { CopyOutlined, IdcardOutlined, InfoCircleFilled, UserOutlined, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import _ from 'lodash';
import { Link } from 'ui/helpers/Link';
import history from 'ui/utils/history';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import { sections } from 'ui/constants';
import copyTextToClipboard from 'ui/helpers/copyTextToClipboard';
import isIP from 'ui/helpers/isIP';

const TypedValue = ({ addFilter, additionalLinks, children, printedValue, redirect, value, type }) => {
  let listOfLinks = [
    {
      key: 'copyTextToClipboard',
      label: (
        <div
          onClick={() => {
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

  if (type === 'ip') {
    listOfLinks = [
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
      ...additionalLinks,
      {
        key: 'typedValueIP2',
        label: (
          <div
            onClick={() => {
              addFilter(sections.GLOBAL, {
                id: value || '',
                value: value || '',
                label: `IP: ${value}`,
                fullString: true,
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
            onClick={() => {
              addFilter(sections.GLOBAL, {
                id: value,
                value: value,
                label: `IP: ${value}`,
                fullString: true,
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
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (type === 'port') {
    listOfLinks = [
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
      ...additionalLinks,
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (type === 'hostname') {
    listOfLinks = [
      ...listOfLinks,
      {
        key: 'typedValueHostname',
        label: (
          <a href={`https://www.virustotal.com/gui/${isIP(encodeURIComponent(value)) ? 'ip-address' : 'domain'}/${value}`} target="_blank">
            <InfoCircleFilled /> <span>External info</span>
          </a>
        ),
      },
      ...additionalLinks,
    ].filter(obj => !_.isEmpty(obj.label));
  }

  if (type === 'username') {
    listOfLinks = [
      ...listOfLinks,
      {
        key: 'typedValueUsername',
        label: (
          <div
            onClick={() => {
              addFilter(sections.GLOBAL, {
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
      ...additionalLinks,
    ].filter(obj => !_.isEmpty(obj.label));
  }

  if (type !== 'ip' && type !== 'port' && type !== 'hostname' && type !== 'username') {
    listOfLinks = [...listOfLinks, ...additionalLinks].filter(obj => !_.isEmpty(obj.label));
  }

  return (
    <Dropdown
      menu={{
        items: listOfLinks,
      }}
      trigger={['click']}
    >
      {children || <a>{value}</a>}
    </Dropdown>
  );
};

TypedValue.defaultProps = {
  additionalLinks: [],
};

TypedValue.propTypes = {
  type: PropTypes.string.isRequired, // 'ip|hostname|username|port'
  value: PropTypes.string.isRequired,
  redirect: PropTypes.bool,
  additionalLinks: PropTypes.arrayOf(PropTypes.object),
  addFilter: PropTypes.func,
  children: PropTypes.object,
  printedValue: PropTypes.string,
};

export default connect(null, { addFilter })(TypedValue);
