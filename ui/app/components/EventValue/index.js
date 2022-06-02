import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import EventValueInfo from 'ui/components/EventValueInfo';
import { sections } from 'ui/constants';
import { Tooltip } from 'antd';
import { InfoCircleFilled, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import ErrorHandler from 'ui/components/Error';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import isIP from 'ui/helpers/isIP';
import styled from 'styled-components';
import copyTextToClipboard from 'ui/helpers/copyTextToClipboard';

// put all the sections where we want to inlclude `virus total links` for ip addresses and domains
const virusTotalLinks = ['hostname_info.domain', 'http.hostname', 'dns.query.rrname', 'http.http_refer_info.domain', 'tls.sni'];
const mitreLinks = [
  'alert.metadata.mitre_tactic_id',
  'alert.metadata.mitre_technique_id',
  'alert.metadata.mitre_tactic_name',
  'alert.metadata.mitre_technique_name',
];

const Container = styled.div`
  display: flex;
  align-items: center;
  background: ${p => p.hover ? '#e5e5e5' : 'none'};
  cursor: ${p => p.hover ? 'pointer' : 'default'};
  padding: 7px 0px;
`
const Value = styled.div`
  flex: 1;
  min-width: 0; /* or some value */
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`

const Extra = styled.div`
  white-space: nowrap;
  display: flex;
  align-items: center;
  span {
    margin-right: 3px;
  }
`

const Badge = styled.span`
  background: #e5e5e5;
  padding: 0px 5px;
  font-size: 12px;
`

const EventValue = (props) => {
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
            href={() => {
              if (props.field === mitreLinks[0]) {
                return `https://attack.mitre.org/tactics/${props.value}`;
              }
              if (!props.value.includes('.')) {
                return `https://attack.mitre.org/techniques/${props.value}`;
              }
              return `https://attack.mitre.org/techniques/${props.value.split('.')[0]}/${props.value.split('.')[1]}`;
            }}
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
  const magnifiers = (!props.copyMode && hover) && props.value !== 'Unknown'
  return (
    <Container
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      hover={props.copyMode && hover}
      onClick={() => {
        if (props.copyMode && hover) {
          copyTextToClipboard(printValue());
        }
      }}
    >
      <Value title={props.value + (props.hasCopyShortcut ? '\nCtrl + left click to copy' : '')}>
        {printValue()}
      </Value>
      {magnifiers && (
        <Extra>
          <ErrorHandler>
            <EventValueInfo field={props.field} value={props.value} magnifiers={magnifiers} />
            {getLink()}
            {/* 256 chars max on ES queries */}
            {((typeof props.value === 'string' && props.value.length < 256) || typeof props.value !== 'string') && (
              <Tooltip title="add a filter on value" trigger="hover" id="tooltip-top">
                <ZoomInOutlined
                  onClick={() =>
                    props.addFilter(sections.GLOBAL, {
                      id: props.field,
                      value: props.value,
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
      )}
      {props.right_info && !(props.copyMode && hover) && <Badge>{props.right_info}</Badge>}
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

const mapDispatchToProps = (dispatch) => ({
  addFilter: (section, filter) => dispatch(addFilter(section, filter)),
});

export default connect(null, mapDispatchToProps)(EventValue);
