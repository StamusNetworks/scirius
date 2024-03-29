import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import EventValueInfo from 'ui/components/EventValueInfo';
import { sections } from 'ui/constants';
import { message, Tooltip } from 'antd';
import { InfoCircleFilled, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import ErrorHandler from 'ui/components/Error';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import isIP from 'ui/helpers/isIP';
import styled from 'styled-components';
import copyTextToClipboard from 'ui/helpers/copyTextToClipboard';
import { COLOR_BOX_HEADER } from 'ui/constants/colors';

// put all the sections where we want to inlclude `virus total links` for ip addresses and domains
const virusTotalLinks = ['hostname_info.domain', 'http.hostname', 'dns.query.rrname', 'http.http_refer_info.domain', 'tls.sni'];
const mitreLinks = [
  'alert.metadata.mitre_tactic_id',
  'alert.metadata.mitre_technique_id',
  'alert.metadata.mitre_tactic_name',
  'alert.metadata.mitre_technique_name',
];

const Container = styled.div`
  display: grid;
  grid-template-columns: 1fr repeat(2, min-content);
  align-items: center;
  width: 100%;
  background: ${p => (p.hover ? '#e5e5e5' : 'none')};
  cursor: ${p => (p.hover ? 'pointer' : 'default')};
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  &:hover .extra {
    visibility: visible;
    opacity: 1;
  }
`;

const Value = styled.div`
  flex: 1;
  min-width: 0; /* or some value */
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const Extra = styled.div`
  white-space: nowrap;
  display: flex;
  align-items: center;
  visibility: hidden;
  opacity: 0;
  transition: all 0.2s;
  span {
    margin-right: 3px;
  }
`;

export const Count = styled.span`
  background: ${COLOR_BOX_HEADER};
  color: #fff;
  padding: 0 5px;
  font-size: 12px;
`;

const EventValue = props => {
  const getLink = () => {
    if (virusTotalLinks.includes(props.field)) {
      return (
        <Tooltip key="virustotal_link" title="external info" trigger="hover" id="tooltip-top">
          <a
            href={`https://www.virustotal.com/gui/${isIP(encodeURIComponent(props.value)) ? 'ip-address' : 'domain'}/${props.value}`}
            target="_blank"
          >
            <InfoCircleFilled />
          </a>
        </Tooltip>
      );
    }
    if (props.field === mitreLinks[0] || props.field === mitreLinks[1]) {
      return (
        <Tooltip key="mitre_link" title="external info" trigger="hover" id="tooltip-top">
          <a
            href={(function () {
              if (props.field === mitreLinks[0]) {
                return `https://attack.mitre.org/tactics/${props.value}`;
              }
              if (!props.value.includes('.')) {
                return `https://attack.mitre.org/techniques/${props.value}`;
              }
              return `https://attack.mitre.org/techniques/${props.value.split('.')[0]}/${props.value.split('.')[1]}`;
            })()}
            target="_blank"
          >
            {' '}
            <InfoCircleFilled />
          </a>
        </Tooltip>
      );
    }
    return false;
  };

  const printValue = () => {
    if (!mitreLinks.includes(props.field)) {
      if (props.format) return props.format(props.value);
      return props.value;
    }
    if (!props.value.toString().includes('_')) return props.value;

    return props.value.toString().replaceAll('_', ' ');
  };

  const [hover, setHover] = useState(false);
  const magnifiers = !props.copyMode && hover && props.value !== 'Unknown';
  return (
    <Container
      data-test="event-value"
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      hover={props.copyMode && hover}
      onClick={() => {
        if (props.copyMode && hover) {
          copyTextToClipboard(printValue());
          message.success({
            duration: 1,
            content: 'Copied!',
          });
        }
      }}
    >
      <Value title={props.value + (props.hasCopyShortcut ? '\nCtrl + left click to copy' : '')} data-test="event-field-value">
        {printValue()}
      </Value>
      <Extra className="extra">
        <ErrorHandler>
          <EventValueInfo field={props.field} value={props.value} magnifiers={magnifiers} />
          {getLink()}
          {/* 256 chars max on ES queries */}
          {((typeof props.value === 'string' && props.value.length < 256) || typeof props.value !== 'string') && (
            <Tooltip title="add a filter on value" trigger="hover" id="tooltip-top">
              <ZoomInOutlined
                onClick={() =>
                  props.addFilter(sections.GLOBAL, {
                    id: props.field || '',
                    value: props.value || '',
                    label: `${props.field}: ${props.format ? props.format(props.value) : props.value}`,
                    fullString: true,
                    negated: false,
                  })
                }
              />
            </Tooltip>
          )}
          {/* 256 chars max on ES queries */}
          {((typeof props.value === 'string' && props.value.length < 256) || typeof props.value !== 'string') && (
            <Tooltip title="add negated filter on value" trigger="hover" id="tooltip-top">
              <ZoomOutOutlined
                onClick={() =>
                  props.addFilter(sections.GLOBAL, {
                    id: props.field,
                    value: props.value,
                    label: `${props.field}: ${props.format ? props.format(props.value) : props.value}`,
                    fullString: true,
                    negated: true,
                  })
                }
              />
            </Tooltip>
          )}
        </ErrorHandler>
      </Extra>
      {props.right_info && !(props.copyMode && hover) && <Count>{props.right_info}</Count>}
    </Container>
  );
};

EventValue.defaultProps = {
  hasCopyShortcut: false,
};

EventValue.propTypes = {
  addFilter: PropTypes.any,
  right_info: PropTypes.any,
  field: PropTypes.any,
  value: PropTypes.any,
  hasCopyShortcut: PropTypes.bool,
  format: PropTypes.func,
  copyMode: PropTypes.bool,
};

const mapDispatchToProps = dispatch => ({
  addFilter: (section, filter) => dispatch(addFilter(section, filter)),
});

export default connect(null, mapDispatchToProps)(EventValue);
