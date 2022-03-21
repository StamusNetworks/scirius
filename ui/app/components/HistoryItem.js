import React from 'react';
import PropTypes from 'prop-types';
import moment from 'moment';
import { connect } from 'react-redux';
import { Menu } from 'antd';
import { MailOutlined, TableOutlined, UserOutlined } from '@ant-design/icons';
import { PAGE_STATE, sections } from 'constants';
import { addFilter } from '../containers/App/stores/global';

const HistoryItem = (props) => {
  const date = moment(props.data.date).format('YYYY-MM-DD, hh:mm:ss a');
  const info = [
    <div key="date">
      <p>Date: {date}</p>
    </div>,
    <div key="user">
      <p>
        <UserOutlined /> {props.data.username}
      </p>
    </div>,
  ];
  if (props.data.ua_objects.ruleset && props.data.ua_objects.ruleset.pk) {
    info.push(
      <div key="ruleset">
        <p>
          <TableOutlined /> {props.data.ua_objects.ruleset.value}
        </p>
      </div>,
    );
  }
  if (props.data.ua_objects.rule && props.data.ua_objects.rule.sid) {
    info.push(
      <div key="rule">
        <p>
          <a
            onClick={() => {
              props.addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: props.data.ua_objects.rule.sid, negated: false });
              props.switchPage(PAGE_STATE.rules_list, props.data.ua_objects.rule.sid);
            }}
          >
            <i className="pficon-security" /> {props.data.ua_objects.rule.sid}
          </a>
        </p>
      </div>,
    );
  }

  return (
    <Menu mode="inline" expandIcon={!props.data.comment && <span />} defaultOpenKeys={[props.expand_row && props.data.pk]}>
      <Menu.SubMenu
        key={props.data.pk}
        icon={<MailOutlined style={{ fontSize: '21px' }} />}
        title={
          <div style={{ display: 'flex' }}>
            <span>{props.data.title}</span>
            <span>{props.data.description}</span>
            <span style={{ display: 'flex' }}>{info}</span>
          </div>
        }
      >
        {props.data.comment && (
          <Menu.Item key={props.data.comment} style={{ height: '100%' }}>
            <strong>Comment</strong>
            <div>{props.data.comment}</div>
          </Menu.Item>
        )}
        {props.data.client_ip && (
          <Menu.Item key={props.data.client_ip} style={{ height: '100%' }}>
            <strong>IP</strong>
            <div>{props.data.client_ip}</div>
          </Menu.Item>
        )}
      </Menu.SubMenu>
    </Menu>
  );
};

HistoryItem.propTypes = {
  data: PropTypes.any,
  switchPage: PropTypes.any,
  expand_row: PropTypes.any,
  addFilter: PropTypes.func,
};

const mapDispatchToProps = {
  addFilter,
};

export default connect(null, mapDispatchToProps)(HistoryItem);
