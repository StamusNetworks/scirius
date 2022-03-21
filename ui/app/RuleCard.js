import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Spin } from 'antd';
import { ZoomInOutlined } from '@ant-design/icons';
import { sections } from 'constants';
import RuleEditKebab from 'ui/components/RuleEditKebab';
import SciriusChart from 'ui/components/SciriusChart';
import ErrorHandler from 'ui/components/Error';
import { addFilter } from 'ui/containers/HuntApp/stores/global';

const RuleCard = (props) => {
  const { category } = props.data;
  const source = props.sources[category.source];
  let catTooltip = category.name;
  if (source && source.name) {
    catTooltip = `${source.name}: ${category.name}`;
  }
  let imported;
  if (!props.data.created) {
    [imported] = props.data.imported_date.split('T');
  }

  const kebabConfig = { rule: props.data };
  return (
    <div className="col-xs-6 col-sm-4 col-md-4">
      <div className="card-pf rule-card">
        <div className="card-pf-heading">
          <h2 className="card-pf-title truncate-overflow" data-toggle="tooltip" title={props.data.msg}>
            {props.data.msg}
          </h2>
          <RuleEditKebab key={`kebab-${props.data.sid}`} config={kebabConfig} rulesets={props.rulesets} />
        </div>
        <div className="card-pf-body">
          <div className="container-fluid">
            <div className="row">
              <div className="col-md-5 truncate-overflow" data-toggle="tooltip" title={catTooltip}>
                Cat: {category.name}
              </div>
              <div className="col-md-4">
                {props.data.created && <p>Created: {props.data.created}</p>}
                {!props.data.created && <p>Imported: {imported}</p>}
              </div>
              <div className="col-md-3">
                Alerts
                <Spin spinning={props.data.hits === undefined}>
                  <span className="badge">{props.data.hits}</span>
                </Spin>
              </div>
            </div>
          </div>
          <Spin spinning={props.data.hits === undefined}>
            {props.data.timeline && (
              <div className="chart-pf-sparkline">
                <ErrorHandler>
                  <SciriusChart
                    data={props.data.timeline}
                    axis={{
                      x: { show: false, min: props.filterParams.fromDate, max: props.filterParams.toDate },
                      y: { show: false },
                    }}
                    legend={{ show: false }}
                    size={{ height: 60 }}
                    point={{ show: false }}
                  />
                </ErrorHandler>
              </div>
            )}
            {!props.data.timeline && (
              <div className="no-sparkline">
                <p>No alert</p>
              </div>
            )}
          </Spin>
          <div>
            SID: <strong>{props.data.sid}</strong>
            <span className="pull-right">
              <a
                onClick={() => props.addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: props.data.sid, negated: false })}
                style={{ cursor: 'pointer' }}
              >
                <ZoomInOutlined />
              </a>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

RuleCard.propTypes = {
  data: PropTypes.any,
  sources: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
  rulesets: PropTypes.any,
  addFilter: PropTypes.func,
};

const mapDispatchToProps = {
  addFilter,
};

export default connect(null, mapDispatchToProps)(RuleCard);
