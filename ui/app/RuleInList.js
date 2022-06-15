import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { List, Spin } from 'antd';
import { SafetyOutlined, ZoomInOutlined } from '@ant-design/icons';
import { sections } from 'ui/constants';
import RuleEditKebab from 'ui/components/RuleEditKebab';
import SciriusChart from 'ui/components/SciriusChart';
import EventValue from 'ui/components/EventValue';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import UICollapse from 'ui/components/UIElements/UICollapse';
import UIPanel from 'ui/components/UIElements/UIPanel/UIPanel';
import UIPanelHeader from 'ui/components/UIElements/UIPanel/UIPanelHeader';

const RuleInList = (props) => (
    <UICollapse>
      {props.rules.map(rule => {
        const { category } = rule;
        const source = props.sources[category.source];
        let catTooltip = category.name;
        if (source && source.name) {
          catTooltip = `${source.name}: ${category.name}`;
        }
        const kebabConfig = { rule };

        return <UIPanel
          key={`${rule.sid}-submenu`}
          showArrow={false}
          extra={
            <React.Fragment>
                {!rule.hits && rule.hits !== 0 ? (
                  <Spin size="small" />
                ) : (
                  <div>
                    <strong>alerts</strong>: {rule.hits}
                  </div>
                )}
              <a
                role="button"
                key={`actions-${rule.sid}`}
                style={{margin: '0 10px 0 10px'}}
                onClick={() => props.addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: rule.sid, negated: false })}
              >
                <ZoomInOutlined />
              </a>
              <RuleEditKebab key={`kebab-${rule.sid}`} config={kebabConfig} rulesets={props.rulesets} />
            </React.Fragment>
          }
          header={<UIPanelHeader
                sub1={<SafetyOutlined style={{fontSize: '18px'}}/>}
                sub2={rule.sid}
                sub3={<div>{rule.msg}</div>}
                sub4={<React.Fragment>
                    <div><strong>created</strong>: {rule.created}</div>
                    <div><strong>updated</strong>: {rule.updated}</div>
                    <div data-toggle="tooltip" title={catTooltip}><strong>category</strong>: {category.name}</div>
                  </React.Fragment>}
          />}
        >
            {rule.timeline && (
             <div key="item1" style={{ height: '100%' }}>
               <div className="row">
                 {/* eslint-disable-next-line react/no-danger */}
                 <div className="SigContent" dangerouslySetInnerHTML={{ __html: rule.content }}></div>
               </div>
               <div className="row">
                 <div className="col-md-12">
                   <SciriusChart
                     data={rule.timeline}
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
                     dataSource={rule.probes}
                     renderItem={(item) => (
                       <List.Item key={item.probe}>
                         <EventValue field="host" value={item.probe} right_info={<span className="badge">{item.hits}</span>} />
                       </List.Item>
                     )}
                   />
                 </div>
               </div>
             </div>
           )}
        </UIPanel>
      })}
    </UICollapse>
  );

RuleInList.propTypes = {
  rules: PropTypes.any,
  sources: PropTypes.any,
  rulesets: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
  addFilter: PropTypes.any,
};

const mapDispatchToProps = {
  addFilter,
};

export default connect(null, mapDispatchToProps)(RuleInList);
