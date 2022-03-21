import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { List, Menu, Spin } from 'antd';
import { SafetyOutlined, ZoomInOutlined } from '@ant-design/icons';
import { sections } from 'hunt_common/constants';
import RuleEditKebab from './components/RuleEditKebab';
import SciriusChart from './components/SciriusChart';
import EventValue from './components/EventValue';
import { addFilter } from './containers/HuntApp/stores/global';

const RuleInList = (props) => {
  const { SubMenu } = Menu;
  const { category } = props.data;
  const source = props.sources[category.source];
  let catTooltip = category.name;
  if (source && source.name) {
    catTooltip = `${source.name}: ${category.name}`;
  }
  const kebabConfig = { rule: props.data };
  return (
    <Menu mode="inline">
      <SubMenu
        key="sub1"
        icon={<SafetyOutlined style={{ fontSize: '27px' }} />}
        title={
          <div>
            <span>{props.data.sid}</span>
            <span>{props.data.msg}</span>
            <span>Created: {props.data.created}</span>
            <span>Updated: {props.data.updated}</span>
            <span data-toggle="tooltip" title={catTooltip}>
              Category: {category.name}
            </span>
            <span>
              {!props.data.hits && props.data.hits !== 0 ? (
                <Spin size="small" />
              ) : (
                <span>
                  Alerts <span className="badge">{props.data.hits}</span>
                </span>
              )}
            </span>
            <span>
              <a
                role="button"
                key={`actions-${props.data.sid}`}
                onClick={() => props.addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: props.data.sid, negated: false })}
              >
                <ZoomInOutlined />
              </a>
            </span>
            <span>
              <RuleEditKebab key={`kebab-${props.data.sid}`} config={kebabConfig} rulesets={props.rulesets} />
            </span>
          </div>
        }
      >
        {props.data.timeline && (
          <Menu.Item key="item1" style={{ height: '100%' }}>
            <div className="row">
              {/* eslint-disable-next-line react/no-danger */}
              <div className="SigContent" dangerouslySetInnerHTML={{ __html: props.data.content }}></div>
            </div>
            <div className="row">
              <div className="col-md-12">
                <SciriusChart
                  data={props.data.timeline}
                  axis={{ x: { min: props.filterParams.fromDate, max: props.filterParams.toDate } }}
                  legend={{ show: false }}
                  padding={{ bottom: 10 }}
                />
              </div>
            </div>
            <div className="row">
              <div className="col-md-4">
                <h4>Probes</h4>
                <List
                  size="small"
                  header={null}
                  footer={null}
                  dataSource={props.data.probes}
                  renderItem={(item) => (
                    <List.Item key={item.probe}>
                      <EventValue field="host" value={item.probe} right_info={<span className="badge">{item.hits}</span>} />
                    </List.Item>
                  )}
                />
              </div>
            </div>
          </Menu.Item>
        )}
      </SubMenu>
    </Menu>
  );
};

RuleInList.propTypes = {
  data: PropTypes.any,
  sources: PropTypes.any,
  rulesets: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
  addFilter: PropTypes.any,
};

const mapDispatchToProps = {
  addFilter,
};

export default connect(null, mapDispatchToProps)(RuleInList);
