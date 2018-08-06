/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/


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
