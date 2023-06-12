import React from 'react';
import PropTypes from 'prop-types';

import ErrorHandler from 'ui/components/Error';
import DonutChart from 'ui/components/DonutChart';
import { buildQFilter } from 'ui/buildQFilter';
import { withStore } from 'ui/mobx/RootStoreProvider';

class HuntTrend extends React.Component {
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

  async fetchData() {
    const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
    const data = await this.props.store.esStore.fetchAlertsCount(qfilter);
    if (typeof data !== 'string') {
      this.setState({ data });
    }
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
  store: PropTypes.object,
};

export default withStore(HuntTrend);
