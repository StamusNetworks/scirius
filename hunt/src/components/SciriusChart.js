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


import React from 'react';

const c3 = require('c3');

export default class SciriusChart extends React.Component {
    constructor(props) {
        super(props);
        // Generate unique ID for the chart
        this.chartId = `chart${Math.random().toString(36).substr(2, 9)}`;
    }

    componentDidMount() {
        this.chartRender(this.props);
    }

    componentWillReceiveProps(nextProps) {
        this.chartRender(nextProps);
    }

    chartRender = (opts) => {
        const newOpts = { ...opts };
        const now = Date.now();
        const axis = {
            x: {
                type: 'timeseries',
                localtime: true,
                min: opts.from_date,
                max: now,
                show: true,
                tick: { format: '%Y-%m-%d %H:%M' }
            }
        }
        if (opts.axis) {
            if (opts.axis.x) {
                axis.x = { ...axis.x, ...opts.axis.x };
            }
            if (opts.axis.y) {
                axis.y = opts.axis.y;
            }
            delete newOpts.axis;
        }

        if (axis.x.show) {
            const timespan = now - opts.from_date;
            let interval = 0;
            let tickMin = 0;
            let tickMax = 0;

            if (Math.floor(timespan / 1000 / 60) <= 2 * 24 * 60) {
                let tickAlign = 0;
                if (Math.floor(timespan / 1000 / 60) <= 60) {
                    // 1 hour
                    interval = 10 * 60 * 1000;
                    tickAlign = 5 * 60 * 1000;
                } else if (Math.floor(timespan / 1000 / 60) <= 6 * 60) {
                    // 6 hour
                    interval = 30 * 60 * 1000;
                    tickAlign = 10 * 60 * 1000;
                } else if (Math.floor(timespan / 1000 / 60) <= 24 * 60) {
                    // 24 hour
                    interval = 2 * 60 * 60 * 1000;
                    tickAlign = 60 * 60 * 1000;
                } else {
                    // 2 days
                    interval = 4 * 60 * 60 * 1000;
                    tickAlign = 60 * 60 * 1000;
                }
                tickMin = Math.ceil(opts.from_date / tickAlign) * tickAlign;
                tickMax = Math.floor(now / tickAlign) * tickAlign;
            } else {
                // Special case when aligning ticks on days, since formula above would aligns on UTC midnight
                if (Math.floor(timespan / 1000 / 60) <= 7 * 24 * 60) {
                    // 7 days
                    interval = 24 * 60 * 60 * 1000;
                } else {
                    // 30 days
                    interval = 3 * 24 * 60 * 60 * 1000;
                }
                const hourTruncate = (d) => {
                    const newDate = new Date(d);
                    newDate.setHours(0);
                    newDate.setMinutes(0);
                    newDate.setSeconds(0);
                    newDate.setMilliseconds(0);
                    return newDate.getTime();
                }
                tickMin = hourTruncate(opts.from_date) + (24 * 60 * 60 * 1000);
                tickMax = hourTruncate(now);
            }

            const tickCount = Math.round((tickMax - tickMin) / interval) + 1;
            let ticks = new Array(tickCount).fill(0);
            ticks = ticks.map((v, i) => (i * interval) + tickMin);
            axis.x.tick.values = ticks;
        }

        c3.generate({
            bindto: `#${this.chartId}`,
            axis,
            ...newOpts
        });
    }

    render() {
        return (<div id={this.chartId}>loading</div>);
    }
}
