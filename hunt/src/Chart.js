import C3Chart from 'react-c3js';
import 'c3/c3.css';

export class SciriusChart extends C3Chart {
  componentWillReceiveProps(newProps) {
          var range = this.chart.axis.min();
          range.x = newProps.from_date;
          this.chart.axis.min(range);
          range = this.chart.axis.max();
          range.x = Date.now();
          this.chart.axis.max(range);
          this.updateChart(newProps);
  }
}
