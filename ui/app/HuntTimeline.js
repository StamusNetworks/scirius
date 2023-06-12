import React from 'react';
import PropTypes from 'prop-types';

import SciriusChart from 'ui/components/SciriusChart';
import ErrorHandler from 'ui/components/Error';
import { buildQFilter } from 'ui/buildQFilter';
import { withStore } from 'ui/mobx/RootStoreProvider';

class HuntTimeline extends React.Component {
  constructor(props) {
    super(props);
    this.state = { data: undefined };
    this.fetchData = this.fetchData.bind(this);
  }

  componentDidMount() {
    this.fetchData();
  }

  componentDidUpdate(prevProps) {
    if (
      JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams) ||
      JSON.stringify(prevProps.filters) !== JSON.stringify(this.props.filters) ||
      JSON.stringify(prevProps.eventTypes) !== JSON.stringify(this.props.eventTypes) ||
      prevProps.chartTarget !== this.props.chartTarget ||
      JSON.stringify(prevProps.systemSettings) !== JSON.stringify(this.props.systemSettings)
    ) {
      this.fetchData();
    }
  }

  async fetchData() {
    const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);

    const res = await this.props.store.esStore.fetchTimeline(this.props.chartTarget, qfilter);
    const prows = { x: [] };

    const keys = Object.keys(res);
    const vals = Object.values(res);
    let key;
    for (let keyNum = 0; keyNum < keys.length; keyNum += 1) {
      key = keys[keyNum];
      if (!['interval', 'from_date'].includes(key)) {
        prows[key] = {};
        for (let entry = 0; entry < vals[keyNum].entries.length; entry += 1) {
          if (prows.x.indexOf(vals[keyNum].entries[entry].time) === -1) {
            prows.x.push(vals[keyNum].entries[entry].time);
          }
          prows[key][vals[keyNum].entries[entry].time] = vals[keyNum].entries[entry].count;
        }
      }
    }

    const pprows = prows.x.slice();
    pprows.sort((a, b) => a - b);
    let putindrows = [''];
    putindrows[0] = pprows;
    putindrows[0].unshift('x');
    const pKeys = Object.keys(prows);
    let k;
    for (let pki = 0; pki < pKeys.length; pki += 1) {
      k = pKeys[pki];
      if (k !== 'x') {
        const pvalue = [k];
        for (let i = 1; i < putindrows[0].length; i += 1) {
          if (putindrows[0][i] in prows[k]) {
            pvalue.push(prows[k][putindrows[0][i]]);
          } else {
            pvalue.push(0);
          }
        }
        putindrows.push(pvalue);
      }
    }
    if (putindrows.length === 1) {
      putindrows = [];
    }

    const data = { data: { x: 'x', columns: putindrows } };

    if (this.props.chartTarget) {
      data.data.colors = {
        relevant: '#ec7a08',
        informational: '#7b1244',
        untagged: '#005792',
      };
    }
    this.setState(data);
  }

  render() {
    return (
      <div style={{ ...this.props.style }}>
        {this.state.data && (
          <ErrorHandler>
            <SciriusChart
              data={this.state.data}
              axis={{ x: { min: this.props.filterParams.fromDate, max: this.props.filterParams.toDate } }}
              padding={{ bottom: 15 }}
              size={{ height: 200 }}
            />
          </ErrorHandler>
        )}
      </div>
    );
  }
}

HuntTimeline.defaultProps = {
  style: {},
};

HuntTimeline.propTypes = {
  filters: PropTypes.any,
  systemSettings: PropTypes.any,
  style: PropTypes.object,
  chartTarget: PropTypes.bool,
  filterParams: PropTypes.object.isRequired,
  eventTypes: PropTypes.object,
  store: PropTypes.object,
};

export default withStore(HuntTimeline);
