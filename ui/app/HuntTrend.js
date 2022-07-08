import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import * as config from 'config/Api';
import { buildQFilter } from 'ui/buildQFilter';
import { buildFilterParams } from 'buildFilterParams';
import ErrorHandler from 'ui/components/Error';
import DonutChart from 'ui/components/DonutChart';

export default class HuntTrend extends React.Component {
  constructor(props) {
    super(props);
    this.state = { data: undefined };
    this.fetchData = this.fetchData.bind(this);
  }

  componentDidMount() {
    this.fetchData();
  }

  componentDidUpdate(prevProps) {
    if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams) || prevProps.filters !== this.props.filters) {
      this.fetchData();
    }
  }

  fetchData() {
    const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
    const filterParams = buildFilterParams(this.props.filterParams);
    axios.get(`${config.API_URL}${config.ES_BASE_PATH}alerts_count/?prev=1&hosts=*&${filterParams}${qfilter}`).then(res => {
      if (typeof res.data !== 'string') {
        this.setState({ data: res.data });
      }
    });
  }

  render() {
    let gData;
    if (this.state.data) {
      gData = {
        columns: [
          ['previous count', this.state.data.prev_doc_count],
          ['current count', this.state.data.doc_count],
        ],
        groups: [['previous count', 'current count']],
      };
    } else {
      gData = {
        columns: [
          ['previous count', 0],
          ['current count', 0],
        ],
        groups: [['previous count', 'current count']],
      };
    }
    return (
      <div>
        <ErrorHandler>
          <DonutChart
            data={{
              columns: gData.columns,
              groups: gData.groups,
              colors: {
                'previous count': '#0088ce',
                'current count': '#737373',
              },
            }}
            legend={{
              show: true,
              position: 'bottom',
            }}
            style={{
              height: '190px',
              margin: '0 auto',
            }}
            donutWidth={12}
            title={{
              show: true,
              pretty: true,
              line1: this.state.data ? this.state.data.doc_count : 0,
              line2: 'current count',
            }}
          />
        </ErrorHandler>
      </div>
    );
  }
}
HuntTrend.propTypes = {
  filters: PropTypes.any,
  systemSettings: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
};
