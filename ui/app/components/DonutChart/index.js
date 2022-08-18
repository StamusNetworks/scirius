import React from 'react';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const c3 = require('c3');
const d3 = require('d3');

const Container = styled.div`
  .c3-chart-arcs-title {
    fill: black;
    font-size: 22px !important;
  }
`;

class DonutChart extends React.Component {
  constructor(props) {
    super(props);
    this.chart = null;
    // Generate unique ID for the chart
    this.chartId = `chart${Math.random().toString(36).substr(2, 9)}`;
  }

  componentDidMount() {
    this.chart = c3.generate({
      bindto: `#${this.chartId}`,
      data: {
        ...this.props.data,
        type: 'donut',
      },
      donut: {
        title: '',
        width: this.props.donutWidth,
        label: {
          show: false,
        },
      },
      tooltip: { ...this.props.tooltip },
      legend: { ...this.props.legend },
    });
    if (typeof this.props.title.line1 !== 'undefined') {
      d3.select('.c3-chart-arcs-title')
        .append('tspan')
        .attr('class', 'donut-title-line1')
        .attr('dy', typeof this.props.title.line2 !== 'undefined' ? 0 : 2) // set title line 1 vertically centered if line 2 does not exists
        .attr('x', 0)
        .style('font-size', '30px')
        .style('font-weight', '300');
    }
    if (typeof this.props.title.line2 !== 'undefined') {
      d3.select('.c3-chart-arcs-title')
        .append('tspan')
        .attr('class', 'donut-title-line2')
        .attr('dy', 24)
        .attr('x', 0)
        .style('font-size', '12px')
        .style('font-weight', '400');
    }
  }

  componentDidUpdate(prevProps) {
    if (JSON.stringify(prevProps.data.columns) !== JSON.stringify(this.props.data.columns)) {
      this.chart.load({
        columns: this.props.data.columns,
      });

      // Work-around, force showing the legend since it's not displayed on 1st page load
      this.chart.legend.show();
    }
    if (this.props.title.show) {
      this.setTitle(this.makeTitle(this.props.title.line1));
    }
  }

  bigNumFormatter = number => {
    let res = number.toString();
    if (number > 999999999) {
      res = `${(number / 1000000000).toFixed(1)}B`;
    } else if (number > 999999) {
      res = `${(number / 1000000).toFixed(1)}M`;
    } else if (number > 999) {
      res = `${(number / 1000).toFixed(1)}k`;
    }
    return res;
  };

  setTitle = title => {
    d3.select('.donut-title-line1').text(title);
    d3.select('.donut-title-line2').text(this.props.title.line2);
  };

  makeTitle = type => {
    let title = '';
    const sum = this.props.data.columns.reduce((acc, x) => acc + x[1], 0);

    switch (type) {
      case 'total':
        title = Math.round(sum).toString();
        break;
      default:
        title = this.props.title.line1;
        break;
    }

    return this.props.title.pretty ? this.bigNumFormatter(title) : title;
  };

  render() {
    return <Container id={this.chartId} style={{ width: this.props.width, height: this.props.height, ...this.props.style }} />;
  }
}

DonutChart.defaultProps = {
  donutWidth: 10,
  title: {
    show: false,
    pretty: false,
    line1: null,
    line2: null,
  },
  tooltip: {
    show: false,
  },
};

DonutChart.propTypes = {
  donutWidth: PropTypes.number,
  style: PropTypes.object,
  width: PropTypes.number,
  height: PropTypes.number,
  data: PropTypes.object,
  legend: PropTypes.object,
  title: PropTypes.shape({
    show: PropTypes.bool,
    pretty: PropTypes.bool,
    line1: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    line2: PropTypes.string,
  }),
  tooltip: PropTypes.shape({
    show: PropTypes.bool,
  }),
};

export default DonutChart;
