import React from 'react';
import PropTypes from 'prop-types';
import { Link } from 'ui/helpers/Link';
import { Dropdown } from 'antd';
import { IdcardOutlined } from '@ant-design/icons';
import _ from 'lodash';
// import { IP_FIELDS } from 'components/FilterList/FilterList';

const TypedValue = props => {
  let listOfLinks;

  if (props.type === 'ip') {
    listOfLinks = [
      {
        key: '3',
        label: (
          <Link to={`/stamus/hunting/hosts/host-insight/${props.value}`}>
            <div>
              <IdcardOutlined /> <span>host-insight</span>
            </div>
          </Link>
        ),
      },
      ...props.additionalLinks,
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  return (
    <Dropdown
      menu={{
        items: listOfLinks,
      }}
      trigger={['click']}
      onClick={e => {
        // e.stopPropagation();
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
  additionalLinks: PropTypes.arrayOf(PropTypes.string),
};

export default TypedValue;
