import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Dropdown } from 'antd';
import { IdcardOutlined, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import _ from 'lodash';
import { Link } from 'ui/helpers/Link';
import history from 'ui/utils/history';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import { sections } from 'ui/constants';
// import { IP_FIELDS } from 'components/FilterList/FilterList';

const TypedValue = props => {
  let listOfLinks;

  if (props.type === 'ip') {
    listOfLinks = [
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

  return (
    <Dropdown
      menu={{
        items: listOfLinks,
      }}
      trigger={['click']}
      onClick={e => {
        e.stopPropagation();
      }}
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
};

export default connect(null, { addFilter })(TypedValue);
