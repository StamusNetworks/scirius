import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Icon } from 'patternfly-react';
import EventValueInfo from 'hunt_common/components/EventValueInfo';
import { sections } from 'hunt_common/constants';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';
import ErrorHandler from './Error';
import { addFilter } from '../containers/App/stores/global';
import isIP from '../helpers/isIP';

// put all the sections where we want to inlclude `virus total links` for ip addresses and domains
const virusTotalLinks = ['hostname_info.domain', 'http.hostname', 'dns.query.rrname', 'http.http_refer_info.domain', 'tls.sni'];
const mitreLinks = [
  'alert.metadata.mitre_tactic_id',
  'alert.metadata.mitre_technique_id',
  'alert.metadata.mitre_tactic_name',
  'alert.metadata.mitre_technique_name',
];

const EventValue = (props) => {
  const getLink = () => {
    if (virusTotalLinks.includes(props.field)) {
      return (
        <OverlayTrigger
          key="virustotal_link"
          trigger={['hover', 'hover']}
          placement="top"
          overlay={<Tooltip id="tooltip-top">external info</Tooltip>}
        >
          <a
            href={`https://www.virustotal.com/gui/${isIP(encodeURIComponent(props.value)) ? 'ip-address' : 'domain'}/${props.value}`}
            target="_blank"
          >
            {' '}
            <Icon type="fa" name="info-circle" />
          </a>
        </OverlayTrigger>
      );
    }
    if (props.field === mitreLinks[0] || props.field === mitreLinks[1]) {
      return (
        <OverlayTrigger key="mitre_link" trigger={['hover', 'hover']} placement="top" overlay={<Tooltip id="tooltip-top">external info</Tooltip>}>
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
            <Icon type="fa" name="info-circle" />
          </a>
        </OverlayTrigger>
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

  return (
    <div className="value-field-complete">
      <span className="value-field" title={props.value + (props.hasCopyShortcut ? '\nCtrl + left click to copy' : '')}>
        {printValue()}
      </span>
      <span className="value-actions">
        <ErrorHandler>
          <EventValueInfo field={props.field} value={props.value} magnifiers={props.magnifiers} />
          {getLink()}
          {/* 256 chars max on ES queries */}
          {props.magnifiers && ((typeof props.value === 'string' && props.value.length < 256) || typeof props.value !== 'string') && (
            <OverlayTrigger trigger={['hover', 'hover']} placement="top" overlay={<Tooltip id="tooltip-top">add a filter on value</Tooltip>}>
              <a
                onClick={() =>
                  props.addFilter(sections.GLOBAL, {
                    id: props.field,
                    value: props.value,
                    label: `${props.field}: ${props.format ? props.format(props.value) : props.value}`,
                    fullString: true,
                    negated: false,
                  })
                }
              >
                {' '}
                <Icon type="fa" name="search-plus" />
              </a>
            </OverlayTrigger>
          )}
          {/* 256 chars max on ES queries */}
          {props.magnifiers && ((typeof props.value === 'string' && props.value.length < 256) || typeof props.value !== 'string') && (
            <OverlayTrigger trigger={['hover', 'hover']} placement="top" overlay={<Tooltip id="tooltip-top">add negated filter on value</Tooltip>}>
              <a
                onClick={() =>
                  props.addFilter(sections.GLOBAL, {
                    id: props.field,
                    value: props.value,
                    label: `${props.field}: ${props.format ? props.format(props.value) : props.value}`,
                    fullString: true,
                    negated: true,
                  })
                }
              >
                {' '}
                <Icon type="fa" name="search-minus" />
              </a>
            </OverlayTrigger>
          )}
        </ErrorHandler>
      </span>
      {props.right_info && <span className="value-right-info">{props.right_info}</span>}
    </div>
  );
};

EventValue.defaultProps = {
  magnifiers: true,
  hasCopyShortcut: false,
};

EventValue.propTypes = {
  addFilter: PropTypes.any,
  right_info: PropTypes.any,
  field: PropTypes.any,
  value: PropTypes.any,
  magnifiers: PropTypes.bool,
  hasCopyShortcut: PropTypes.bool,
  format: PropTypes.func,
};

const mapDispatchToProps = (dispatch) => ({
  addFilter: (section, filter) => dispatch(addFilter(section, filter)),
});

export default connect(null, mapDispatchToProps)(EventValue);
