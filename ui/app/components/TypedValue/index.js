import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Dropdown, message } from 'antd';
import { CopyOutlined, IdcardOutlined, InfoCircleFilled, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import _ from 'lodash';
import { Link } from 'ui/helpers/Link';
import history from 'ui/utils/history';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import { sections } from 'ui/constants';
import copyTextToClipboard from 'ui/helpers/copyTextToClipboard';
import isIP from 'ui/helpers/isIP';

const TypedValue = props => {
  let listOfLinks = [
    {
      key: 'copyTextToClipboard',
      label: (
        <div
          onClick={() => {
            copyTextToClipboard(props.printedValue);
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

  if (props.type === 'ip') {
    listOfLinks = [
      ...listOfLinks,
      {
        key: 'typedValueIP1',
        label: (
          <Link to={`/stamus/hunting/hosts/host-insight/${props.value}`}>
            <div>
              <IdcardOutlined /> <span>host-insight</span>
            </div>
          </Link>
        ),
      },
      ...props.additionalLinks,
      {
        key: 'typedValueIP2',
        label: (
          <div
            onClick={() => {
              props.addFilter(sections.GLOBAL, {
                id: props.value || '',
                value: props.value || '',
                label: `IP: ${props.value}`,
                fullString: true,
                negated: false,
              });
              if (props.redirect) history.push('/stamus/hunting/dashboards');
            }}
          >
            <ZoomInOutlined /> <span>filter on IP: {props.value}</span>
          </div>
        ),
      },
      {
        key: 'typedValueIP3',
        label: (
          <div
            onClick={() => {
              props.addFilter(sections.GLOBAL, {
                id: props.value,
                value: props.value,
                label: `IP: ${props.value}`,
                fullString: true,
                negated: true,
              });
              if (props.redirect) history.push('/stamus/hunting/dashboards');
            }}
          >
            <ZoomOutOutlined /> <span>negated filter on IP: {props.value}</span>
          </div>
        ),
      },
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (props.type === 'port') {
    listOfLinks = [
      ...listOfLinks,
      {
        key: 'typedValuePort',
        label: (
          <a href={`https://www.dshield.org/port.html?port=${props.value}`} target="_blank">
            <div>
              <InfoCircleFilled /> <span>external info</span>
            </div>
          </a>
        ),
      },
      ...props.additionalLinks,
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (props.type === 'hostname') {
    listOfLinks = [
      ...listOfLinks,
      {
        key: 'typedValueHostname',
        label: (
          <a
            href={`https://www.virustotal.com/gui/${isIP(encodeURIComponent(props.value)) ? 'ip-address' : 'domain'}/${props.value}`}
            target="_blank"
          >
            <InfoCircleFilled /> <span>external info</span>
          </a>
        ),
      },
      ...props.additionalLinks,
    ].filter(obj => !_.isEmpty(obj.label));
  }

  return (
    <Dropdown
      menu={{
        items: listOfLinks,
      }}
      trigger={['click']}
    >
      {props.children || <a>{props.value}</a>}
    </Dropdown>
  );
};

TypedValue.defaultProps = {
  additionalLinks: [],
};

TypedValue.propTypes = {
  type: PropTypes.string.isRequired, // 'ip|hostname|username|port'
  value: PropTypes.string.isRequired, // '10.136.0.33',
  redirect: PropTypes.bool,
  additionalLinks: PropTypes.arrayOf(PropTypes.object),
  addFilter: PropTypes.func,
  children: PropTypes.object,
  printedValue: PropTypes.string,
};

export default connect(null, { addFilter })(TypedValue);
