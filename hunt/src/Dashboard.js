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
import axios from 'axios';
import { DonutChart } from 'patternfly-react';
import { WidthProvider, Responsive } from "react-grid-layout";
import store from 'store';
import map from "lodash/map";
import reject from "lodash/reject";
import find from "lodash/find";
import {Badge, ListGroup, ListGroupItem} from "react-bootstrap";
import { buildQFilter } from './helpers/buildQFilter';
import { RuleToggleModal } from './Rule.js';
import { HuntList } from './Api.js';
import { HuntFilter } from './Filter.js';
import * as config from './config/Api.js';
import { SciriusChart } from './Chart.js';
import {EventValue} from "./Event";
import "../node_modules/react-grid-layout/css/styles.css";
import '../node_modules/react-resizable/css/styles.css';
import { Modal, DropdownKebab, MenuItem } from 'patternfly-react';

const ResponsiveReactGridLayout = WidthProvider(Responsive);

export class HuntDashboard extends HuntList {
    constructor(props) {
        super(props);

        let only_hits = localStorage.getItem("rules_list.only_hits");
        if (!only_hits) {
            only_hits = false;
        }

        this.panelAutoresize = false;
        this.panelState = {};
        this.panelsLoaded = 0;
        this.panelsBooted = 'no';
        this.panelsAdjusted = false;
        this.breakPointChanged = false;
        this.storedMicroLayout = [];
        this.storedMacroLayout = [];
        this.qFilter = "";
        this.filters = "";

        this.state = {
            load: ['metadata', 'basic', 'organizational', 'ip', 'http', 'dns', 'tls', 'smtp', 'smb', 'ssh'],
            // load: ['basic'],
            breakPoint: 'lg',
            dashboard: config.dashboard.sections,
            rules: [], sources: [], rulesets: [], rules_count: 0,
            loading: true,
            refresh_data: false,
            view: 'rules_list',
            display_toggle: true,
            only_hits: only_hits,
            action: { view: false, type: 'suppress' },
            net_error: undefined,
            rules_filters: [],
            supported_actions: [],
            moreModal: null,
            moreResults: [],
            editMode: false,
        };
    }

    componentDidUpdate(prevProps, prevState) {
        // An adjustment of the panels height is needed for their first proper placement
        if (this.panelsBooted === 'yes' && !this.panelsAdjusted) {
            this.panelsAdjusted = true;
            this.adjustPanelsHeight();
        }

        if (typeof this.props.system_settings !== 'undefined') {

            this.qFilter = this.generateQFilter();
            this.storedMicroLayout = store.get('dashboardMicroLayout');
            this.storedMacroLayout = store.get('dashboardMаcroLayout');
            // Initial booting of panels were moved here instead of componentDidMount, because of the undefined system_settings in componentDidMount
            if (this.panelsBooted === 'no') {
                this.bootPanels();
            } else {
                if (!this.filters.length) {
                    this.filters = JSON.stringify(this.props.filters);
                } else {
                    if (this.panelsBooted !== 'booting' && (this.filters !== JSON.stringify(this.props.filters) || prevProps.from_date !== this.props.from_date)) {
                        this.filters = JSON.stringify(this.props.filters);
                        this.bootPanels();
                    }
                }
            }
        }

    }

    componentDidMount() {
        if (this.state.rulesets.length === 0) {
            axios.get(config.API_URL + config.RULESET_PATH).then(res => {
                this.setState({ rulesets: res.data['results'] });
            })
        }
        axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(
            res => {
                var fdata = [];
                for (var i in res.data) {
                    /* Only ES filter are allowed for Alert page */
                    if (['filter'].indexOf(res.data[i].queryType) !== -1) {
                        if (res.data[i].filterType !== 'hunt') {
                            fdata.push(res.data[i]);
                        }
                    }
                }
                this.setState({ rules_filters: fdata });
            }
        );

        let timeout = false;
        window.addEventListener('resize', function () {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                if (typeof(Event) === 'function') {
                    // modern browsers
                    window.dispatchEvent(new Event('resize'));
                } else {
                    // for IE and other old browsers
                    // causes deprecation warning on modern browsers
                    var evt = window.document.createEvent('UIEvents');
                    evt.initUIEvent('resize', true, false, window, 0);
                    window.dispatchEvent(evt);
                }
            }, 250);
        });

        if( this.props.filters.length ){
            this.loadActions(this.props.filters);
        }
    }

    getBlockFromLS = (panel, block, breakPoint) => {
        let result = {};
        if (typeof this.storedMicroLayout !== 'undefined' && typeof this.storedMicroLayout[panel] !== 'undefined' && typeof this.storedMicroLayout[panel][breakPoint] !== 'undefined') {
            result = find(this.storedMicroLayout[panel][breakPoint], { 'i': block })
        }
        return result;
    };

    getPanelFromLS = (panel) => {
        let result = {};
        if (typeof this.storedMacroLayout !== 'undefined' && typeof this.storedMacroLayout[panel] !== 'undefined') {
            result = find(this.storedMacroLayout, { 'i': panel })
        }
        return result;
    };

    generateQFilter = () => {
        let qfilter = buildQFilter(this.props.filters, this.props.system_settings);
        if (qfilter) {
            qfilter = '&qfilter=' + qfilter;
        } else {
            qfilter = "";
        }
        return qfilter;
    }

    bootPanels = () => {
        this.panelsLoaded = 0;
        this.panelsBooted = 'booting';
        this.panelState.dashboard = { ...this.state.dashboard };
        map(this.state.load, panel => this.bootPanel(panel));
    }

    bootPanel = (panel) => {
        // Count the number of the blocks
        let blocksLoaded = 0;
        let newHeight = 0;
        map(this.state.dashboard[panel].items, block => {

            axios.get(config.API_URL + config.ES_BASE_PATH +
                'field_stats&field=' + block.i +
                '&from_date=' + this.props.from_date +
                '&page_size=5' + this.qFilter)
            .then(json => {

                // Validation of the data property
                if (typeof json.data === 'undefined' || json.data === null) { json.data = [] };

                // When all of the blocks from a single panel are loaded, then mark the panel as loaded
                blocksLoaded++;
                if (blocksLoaded === this.state.dashboard[panel].items.length) {
                    this.panelsLoaded++;
                }

                const height = Math.ceil((json.data.length * config.dashboard.block.defaultItemHeight + config.dashboard.block.defaultHeadHeight) / 13);
                const panelHeight = (json.data.length) ? 10 + (json.data.length * config.dashboard.block.defaultItemHeight) + config.dashboard.block.defaultHeadHeight + config.dashboard.panel.defaultHeadHeight : config.dashboard.panel.defaultHeadHeight;
                const isPanelLoaded = (!this.state.dashboard[panel].items.find(itm => itm.data !== null && itm.data.length === 0));

                const items = this.panelState.dashboard[panel].items.map(el => {
                    if (el.i === block.i) {
                        let data = (json.data.length) ? json.data : null;
                        let extended = {
                            data: data,
                            dimensions: {
                                ...el.dimensions,
                                lg: {
                                    ...el.dimensions.lg,
                                    ...this.getBlockFromLS(panel, block.i, 'lg'),
                                    maxH: height,
                                    minH: height,
                                    h: height,
                                },
                                md: {
                                    ...el.dimensions.md,
                                    ...this.getBlockFromLS(panel, block.i, 'md'),
                                    maxH: height,
                                    minH: height,
                                    h: height,
                                },
                                sm: {
                                    ...el.dimensions.sm,
                                    ...this.getBlockFromLS(panel, block.i, 'sm'),
                                    maxH: height,
                                    minH: height,
                                    h: height,
                                },
                                xs: {
                                    ...el.dimensions.xs,
                                    ...this.getBlockFromLS(panel, block.i, 'xs'),
                                    maxH: height,
                                    minH: height,
                                    h: height,
                                },
                            }
                        };
                        return Object.assign({}, el, extended);
                    }
                    return el;
                });

                newHeight = (newHeight < panelHeight) ? panelHeight : newHeight;
                this.panelState = {
                    dashboard: {
                        ...this.panelState.dashboard,
                        [panel]: {
                            ...this.panelState.dashboard[panel],
                            loaded: isPanelLoaded,
                            dimensions: {
                                ...this.panelState.dashboard[panel].dimensions,
                                h: newHeight,
                                minH: newHeight
                            },
                            items
                        }
                    }
                };

                // When all of the panels are loaded then hit the floor just once
                if (this.panelsLoaded === this.state.load.length) {
                    this.panelsAdjusted = false;
                    if (this.panelsBooted !== 'yes') {
                        this.panelsBooted = 'yes';
                    }
                    this.setState({
                        ...this.state,
                        ...this.panelState,
                    })
                }

            })
        });
    };

    createElement = (block, panel) => {
        this.state.dashboard[panel].items.find(itm => itm.i === block.i).loaded = true;
        let url = config.API_URL + config.ES_BASE_PATH +
            'field_stats&field=' + block.i +
            '&from_date=' + this.props.from_date +
            '&page_size=30' + this.qFilter;
        return (
            <div key={block.i}
                 style={{ background: "white" }}>
                {this.props.children}
                <h3 className={"hunt-stat-title " + ((this.state.editMode) ? 'dashboard-editable-mode' : '')} data-toggle="tooltip" title={block.title}>{block.title}</h3>
                {block.data.length === 5 && <DropdownKebab id={"more-" + this.props.item} pullRight={true}>
                    <MenuItem onClick={(e) => this.loadMore(block, url)} data-toggle="modal">Load more results</MenuItem>
                </DropdownKebab>}
                <div className="hunt-stat-body">
                    <ListGroup>
                        {block.data.map(item => {
                            return (<ListGroupItem key={item.key}>
                                <EventValue field={block.i} value={item.key}
                                            addFilter={this.addFilter}
                                            right_info={<Badge>{item.doc_count}</Badge>}
                                />
                            </ListGroupItem>)
                        })}
                    </ListGroup>
                </div>
            </div>
        );
    };

    getMacroLayouts = () => {
        return this.state.load.map(panel => {
            return {
                ...this.state.dashboard[panel].dimensions, ...this.getPanelFromLS(panel),
                isDraggable: this.state.editMode,
                i: panel.toString()
            };
        });
    };

    getMicroLayouts = (panel, bp) => {
        return this.state.dashboard[panel].items.map(item => {
            // return { ...config.dashboard.block.defaultDimensions, ...item.dimensions, i: item.item.toString() };
            return { ...item.dimensions[bp], i: item.i.toString() };
        });
    };

    resetDashboard = (e) => {
        e.preventDefault();
        let ask = window.confirm("Confirm reset positions of the dashboard panels?");
        if (ask) {
            store.remove('dashboardMacroLayout');
            store.remove('dashboardMicroLayout');
            window.location.reload();
        }
    };

    switchEditMode = (e) => {
        this.setState({
            ...this.state,
            editMode: !this.state.editMode
        })
        e.preventDefault();
    }

    adjustPanelsHeight = (p = null) => {
        let panelsArray = [];

        if (p === null) {
            panelsArray = this.state.load;
        } else {
            panelsArray.push(p);
        }

        let tmpState = this.state;
        let stateChanged = false;
        for (let panel of panelsArray) {
            let panelBodySize = this.getPanelBodySize(panel);
            let panelRealSize = (parseInt(panelBodySize, 10) + parseInt(config.dashboard.panel.defaultHeadHeight, 10));
            if (this.getPanelSize(panel) !== panelRealSize) {
                stateChanged = true;
                tmpState = {
                    ...tmpState,
                    dashboard: {
                        ...tmpState.dashboard,
                        [panel]: {
                            ...tmpState.dashboard[panel],
                            dimensions: {
                                ...tmpState.dashboard[panel].dimensions,
                                h: panelRealSize,
                                minH: panelRealSize,
                            }
                        }
                    }
                };
            }
        }
        if (stateChanged) {
            this.setState(tmpState);
        }
    };

    getPanelSize = panel => parseInt(document.querySelector("#panel-" + panel).style.height.replace('px', ''), 10);

    getPanelBodySize = panel => parseInt(document.querySelector("#panel-" + panel + " div.react-grid-layout").style.height.replace('px', ''), 10);

    onChangeMacroLayout = (macroLayout) => {
        store.set('dashboardMacroLayout', macroLayout);
        let tmpState = this.state.dashboard;
        for (let panel of macroLayout) {
            tmpState = {
                ...tmpState,
                [panel.i]: {
                    ...tmpState[panel.i],
                    dimensions: panel
                }
            }
        }
        this.setState({
            ...this.state,
            dashboard: tmpState
        })
    };

    onDragStartMicro = () => {
        this.panelAutoresize = true;
    };

    onResizeStartMicro = () => {
        this.panelAutoresize = true;
    };

    onChangeMicroLayout = (panel, microLayout) => {
        if (this.panelAutoresize) {
            if (this.state.breakPoint !== null) {
                let ls = store.get('dashboardMicroLayout') || { [panel]: { lg: {}, md: {}, sm: {}, xs: {} } };
                store.set('dashboardMicroLayout', {
                    ...ls,
                    [panel]: {
                        ...ls[panel],
                        [this.state.breakPoint]: microLayout
                    }
                });

                let obj = this.state;
                for (let microItem of microLayout) {
                    obj = {
                        ...obj,
                        dashboard: {
                            ...this.state.dashboard,
                            [panel]: {
                                ...this.state.dashboard[panel],
                                items: this.state.dashboard[panel].items.map((vv, ii) => {
                                    let innerItem = { ...vv };
                                    if (microItem.i === vv.i) {
                                        innerItem.dimensions[this.state.breakPoint] = microItem;
                                    }
                                    return Object.assign({}, vv, innerItem);
                                }),
                            }
                        }
                    };
                };

                this.setState(obj);
            }
            this.adjustPanelsHeight(panel);
            this.panelAutoresize = false;
        } else if (this.breakPointChanged) {
            // Block any further redundant calls
            this.breakPointChanged = false;
            // Execute it with a little delay in order to be sure that the animation will be finished
            setTimeout(() => {
                this.adjustPanelsHeight();
            }, 500);
        }
    };
    onBreakPointChange = (breakpoint, cols, panel) => {
        if (this.state.breakPoint !== breakpoint) {
            this.breakPointChanged = true;
            this.setState({
                ...this.state,
                breakPoint: breakpoint
            });
        }
    };
    loadMore = (item, url) => {
        axios.get(url)
        .then(json => {
            this.setState({ ...this.state, moreModal: item, moreResults: json.data });
        });
    }
    hideMoreModal = () => this.setState({ ...this.state, moreModal: null });
    render() {
        return (
            <div className="HuntList">

                <HuntFilter
                    ActiveFilters={this.props.filters}
                    config={this.props.config}
                    ActiveSort={this.props.config.sort}
                    UpdateFilter={this.UpdateFilter}
                    UpdateSort={this.UpdateSort}
                    setViewType={this.setViewType}
                    filterFields={this.state.rules_filters}
                    sort_config={undefined}
                    displayToggle={undefined}
                    actionsButtons={this.actionsButtons}
                    queryType={['filter']}
                />

                <div className="row">
                    <div className="col-md-10">
                        <HuntTimeline from_date={this.props.from_date} filters={this.props.filters}/>
                    </div>
                    <div className="col-md-2">
                        <HuntTrend from_date={this.props.from_date} filters={this.props.filters}/>
                    </div>
                </div>
                <div className="row">
                    <div className="col-md-12">

                        <div className="pull-right">
                            <a href={"#edit"} onClick={this.switchEditMode}>{(this.state.editMode) ? 'switch off edit mode' : 'edit'}</a>
                            <span> • </span>
                            <a href={"#reset"} onClick={this.resetDashboard}>reset</a>
                        </div>
                        <div className="clearfix"/>

                        {this.panelsBooted !== 'no' && <ResponsiveReactGridLayout margin={[0, 0]} compactType={"vertical"} isResizable={false} rowHeight={1} draggableHandle={".hunt-row-title"} cols={{ lg: 1, md: 1, sm: 1, xs: 1, xxs: 1 }} layouts={{ lg: this.getMacroLayouts(), md: this.getMacroLayouts(), sm: this.getMacroLayouts(), xs: this.getMacroLayouts(), }} onLayoutChange={this.onChangeMacroLayout}>
                            {this.panelsBooted !== 'no' && this.state.load.map((panel) => {
                                    return <div className="hunt-row" key={panel} id={'panel-' + panel}>
                                        <h2 className={"hunt-row-title " + ((this.state.editMode) ? 'dashboard-editable-mode' : '')}>{this.state.dashboard[panel].title}</h2>
                                        <ResponsiveReactGridLayout margin={[3, 3]} compactType={"vertical"}
                                                                   layouts={{
                                                                       lg: this.getMicroLayouts(panel, 'lg'),
                                                                       md: this.getMicroLayouts(panel, 'md'),
                                                                       sm: this.getMicroLayouts(panel, 'sm'),
                                                                       xs: this.getMicroLayouts(panel, 'xs'),
                                                                   }}
                                                                   onDragStart={this.onDragStartMicro}
                                                                   onBreakpointChange={(breakPoint, cols) => this.onBreakPointChange(breakPoint, cols, panel)}
                                                                   onLayoutChange={(e) => this.onChangeMicroLayout(panel, e)}
                                                                   onResizeStart={this.onResizeStartMicro}
                                                                   isDraggable={this.state.editMode} isResizable={this.state.editMode} rowHeight={10}
                                                                   draggableHandle={".hunt-stat-title"}
                                                                   cols={{ lg: 32, md: 24, sm: 16, xs: 8, xxs: 4 }}>
                                            {reject(this.state.dashboard[panel].items, ['data', null]).map((block) => this.createElement(block, panel))}
                                        </ResponsiveReactGridLayout>
                                    </div>
                                }
                            )}
                        </ResponsiveReactGridLayout>}
                    </div>
                </div>

                <RuleToggleModal show={this.state.action.view} action={this.state.action.type} config={this.props.config} filters={this.props.filters} close={this.closeAction} rulesets={this.state.rulesets}/>
                <Modal show={!(this.state.moreModal === null)} onHide={() => { this.hideMoreModal() }}>

                    <Modal.Header>More results <Modal.CloseButton closeText={"Close"} onClick={() => { this.hideMoreModal() }}/> </Modal.Header>
                    <Modal.Body>
                        <div className="hunt-stat-body">
                            <ListGroup>
                                {this.state.moreResults.map(item => {
                                    return (<ListGroupItem key={item.key}>
                                        {this.state.moreModal && <EventValue field={this.state.moreModal.i} value={item.key}
                                                    addFilter={this.addFilter}
                                                    right_info={<Badge>{item.doc_count}</Badge>}
                                        />}
                                    </ListGroupItem>)
                                })}
                            </ListGroup>
                        </div>
                    </Modal.Body>
                </Modal>
            </div>
        );
    }
}


class HuntTrend extends React.Component {
    constructor(props) {
        super(props);
        this.state = { data: undefined };
        this.fetchData = this.fetchData.bind(this);
    }

    fetchData() {
        var string_filters = "";
        var qfilter = buildQFilter(this.props.filters, this.props.system_settings);
        if (qfilter) {
            string_filters += '&filter=' + qfilter;
        }
        axios.get(config.API_URL + config.ES_BASE_PATH +
            'alerts_count&prev=1&hosts=*&from_date=' + this.props.from_date
            + string_filters)
        .then(res => {
            if (typeof(res.data) !== 'string') {
                this.setState({ data: res.data });
            }
        })
    }

    componentDidMount() {
        this.fetchData();
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
        if ((prevProps.from_date !== this.props.from_date) || (prevProps.filters !== this.props.filters)) {
            this.fetchData();
        }
    }

    render() {
        var g_data = undefined;
        if (this.state.data) {
            g_data = {
                columns: [
                    ["previous count", this.state.data.prev_doc_count],
                    ["current count", this.state.data.doc_count]
                ],
                groups: [
                    ["previous count", "current count"]
                ]
            };
        } else {
            g_data = {
                columns: [
                    ["previous count", 0],
                    ["current count", 0]
                ],
                groups: [
                    ["previous count", "current count"]
                ]
            };
        }
        return (
            <div>
                <DonutChart
                    data={g_data}
                    title={{ type: "max" }}
                    tooltip={{ show: true }}
                    legend={{ show: true, position: 'bottom' }}
                />
            </div>
        );
    }
}

class HuntTimeline extends React.Component {
    constructor(props) {
        super(props);
        this.state = { data: undefined };
        this.fetchData = this.fetchData.bind(this);
    }

    fetchData() {
        var string_filters = "";
        var key = undefined;
        var qfilter = buildQFilter(this.props.filters, this.props.system_settings);
        if (qfilter) {
            string_filters += '&filter=' + qfilter;
        }
        axios.get(config.API_URL + config.ES_BASE_PATH +
            'timeline&hosts=*&from_date=' + this.props.from_date + string_filters)
        .then(res => {
            /* iterate on actual row: build x array, for each row build hash x -> value */
            /* sort x array */
            /* for key in x array, build each row, value if exists, 0 if not */
            var prows = { x: [] };
            for (key in res.data) {
                if (!(['interval', 'from_date'].includes(key))) {
                    prows[key] = {};
                    for (var entry in res.data[key].entries) {
                        if (prows['x'].indexOf(res.data[key].entries[entry].time) === -1) {
                            prows['x'].push(res.data[key].entries[entry].time);
                        }
                        prows[key][res.data[key].entries[entry].time] = res.data[key].entries[entry].count;
                    }
                }
            }

            var pprows = prows['x'].slice();
            pprows.sort(function (a, b) { return a - b });
            var putindrows = [''];
            putindrows[0] = pprows;
            putindrows[0].unshift('x');
            for (key in prows) {
                if (key === 'x') {
                    continue;
                }
                var pvalue = [key];
                for (var i = 1; i < putindrows[0].length; i++) {
                    if (putindrows[0][i] in prows[key]) {
                        pvalue.push(prows[key][putindrows[0][i]]);
                    } else {
                        pvalue.push(0);
                    }
                }
                putindrows.push(pvalue);
            }
            if (putindrows.length === 1) {
                putindrows = [];
            }
            this.setState({ data: { x: 'x', columns: putindrows } });
        })
    }

    componentDidMount() {
        this.fetchData();
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
        if ((prevProps.from_date !== this.props.from_date) || (prevProps.filters !== this.props.filters)) {
            this.fetchData();
        }
    }

    render() {
        return (
            <div>
                {this.state.data &&
                <SciriusChart data={this.state.data}
                              axis={{ x: { type: 'timeseries',
                                      localtime: true,
                                      min: this.props.from_date,
                                      max: Date.now(),
                                      tick: { fit: false, rotate: 15, format: '%Y-%m-%d %H:%M' },
                                      show: true
                                  },
                                  y: { show: true }
                              }}
                              legend={{
                                  show: true
                              }}
                              size={{ height: 200 }}
                              point={{ show: true }}
                />
                }
            </div>
        );
    }
}
