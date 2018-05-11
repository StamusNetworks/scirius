import C3Chart from 'react-c3js';
import 'c3/c3.css';

export class SciriusChart extends C3Chart {
  componentWillReceiveProps(newProps) {
          newProps.axis.x.max = Date.now();
          this.chart = undefined;
          this.updateChart(newProps);
  }
}
