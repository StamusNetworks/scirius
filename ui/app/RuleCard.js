import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Card, Row, Col, Spin, Tooltip, Space } from 'antd';
import { ZoomInOutlined } from '@ant-design/icons';
import RuleEditKebab from 'ui/components/RuleEditKebab';
import SciriusChart from 'ui/components/SciriusChart';
import ErrorHandler from 'ui/components/Error';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import Filter from 'ui/utils/Filter';

const RuleCard = props => {
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
    <Card
      title={props.data.msg}
      extra={<RuleEditKebab key={`kebab-${props.data.sid}`} config={kebabConfig} rulesets={props.rulesets} />}
      style={{ margin: '8px 0px' }}
    >
      <Row>
        <Col md={5}>
          <Tooltip overlay={catTooltip}>Cat: {category.name}</Tooltip>
        </Col>
        <Col md={4}>
          {props.data.created && <p>Created: {props.data.created}</p>}
          {!props.data.created && <p>Imported: {imported}</p>}
        </Col>
        <Col md={3}>
          Alerts
          <Spin spinning={props.data.hits === undefined}>
            <span className="badge">{props.data.hits}</span>
          </Spin>
        </Col>
      </Row>
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
      <Space>
        <span>
          SID: <strong>{props.data.sid}</strong>
        </span>
        <a onClick={() => props.addFilter(new Filter(alert.signature_id, props.data.sid, { negated: false }))} style={{ cursor: 'pointer' }}>
          <ZoomInOutlined />
        </a>
      </Space>
    </Card>
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
