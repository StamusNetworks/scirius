/* eslint-disable no-loop-func */
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
import PropTypes from 'prop-types';
import axios from 'axios';
import { Modal, DropdownKebab, MenuItem, Spinner } from 'patternfly-react';
import { WidthProvider, Responsive } from 'react-grid-layout';
import store from 'store';
import md5 from 'md5';
import map from 'lodash/map';
import find from 'lodash/find';
import { Badge, ListGroup, ListGroupItem } from 'react-bootstrap';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import * as config from 'hunt_common/config/Api';
import { dashboard } from 'hunt_common/config/Dashboard';
import { buildQFilter } from 'hunt_common/buildQFilter';
import HuntTimeline from '../../HuntTimeline';
import HuntTrend from '../../HuntTrend';
import RuleToggleModal from '../../RuleToggleModal';
import { actionsButtons, UpdateFilter, loadActions, createAction, closeAction } from '../../helpers/common';
import HuntFilter from '../../HuntFilter';
import EventValue from '../../components/EventValue';
import '../../../node_modules/react-grid-layout/css/styles.css';
import '../../../node_modules/react-resizable/css/styles.css';
import ErrorHandler from '../../components/Error';
import copyTextToClipboard from '../../helpers/copyTextToClipboard';
import { makeSelectAlertTag, makeSelectGlobalFilters, sections } from '../App/stores/global';

const ResponsiveReactGridLayout = WidthProvider(Responsive);

class HuntDashboard extends React.Component {
    constructor(props) {
        super(props);

        let onlyHits = localStorage.getItem('rules_list.only_hits');
        if (!onlyHits) {
            onlyHits = false;
        }

        this.panelAutoresize = false;
        this.panelState = {};
        this.panelsLoaded = 0;
        this.panelsBooted = 'no';
        this.panelsAdjusted = false;
        this.breakPointChanged = false;
        this.storedMicroLayout = [];
        this.storedMacroLayout = [];
        this.qFilter = '';
        this.filters = '';

        const huntFilters = store.get('huntFilters');
        const rulesFilters = (typeof huntFilters !== 'undefined' && typeof huntFilters.dashboard !== 'undefined') ? huntFilters.dashboard.data : [];
        this.state = {
            load: Object.keys(dashboard.sections),
            // load: ['basic'],
            breakPoint: 'lg',
            dashboard: this.extendDefaultPanels(),
            rules: [],
            sources: [],
            rulesets: [],
            rules_count: 0,
            loading: true,
            refresh_data: false,
            view: 'rules_list',
            display_toggle: true,
            onlyHits,
            action: { view: false, type: 'suppress' },
            net_error: undefined,
            rulesFilters,
            supported_actions: [],
            moreModal: null,
            moreResults: [],
            editMode: false,
            chartTarget: false,
            copyMode: false,
            hoveredItem: null,
            copiedItem: '',
        };
        this.actionsButtons = actionsButtons.bind(this);
        this.UpdateFilter = UpdateFilter.bind(this);
        this.createAction = createAction.bind(this);
        this.closeAction = closeAction.bind(this);
        this.loadActions = loadActions.bind(this);
        this.updateRuleListState = props.updateListState.bind(this);
        this.fetchData = () => {};
    }

    componentDidMount() {
        if (this.state.rulesets.length === 0) {
            axios.get(config.API_URL + config.RULESET_PATH).then((res) => {
                this.setState({ rulesets: res.data.results });
            });
        }
        const huntFilters = store.get('huntFilters');
        axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(
            (res) => {
                const fdata = [];
                for (let i = 0; i < res.data.length; i += 1) {
                    /* Only ES filter are allowed for Alert page */
                    if (['filter'].indexOf(res.data[i].queryType) !== -1) {
                        if (res.data[i].filterType !== 'hunt') {
                            fdata.push(res.data[i]);
                        }
                    }
                }
                const currentCheckSum = md5(JSON.stringify(fdata));
                if ((typeof huntFilters === 'undefined' || typeof huntFilters.dashboard === 'undefined') || huntFilters.dashboard.checkSum !== currentCheckSum) {
                    store.set('huntFilters', {
                        ...huntFilters,
                        dashboard: {
                            checkSum: currentCheckSum,
                            data: fdata
                        }
                    });
                    this.setState({ rulesFilters: fdata });
                }
            }
        );

        let timeout = false;
        window.addEventListener('resize', (e) => {
            // Trigger a second resize, to work-around panels not rearranging
            if (e.huntEvent) {
                // work-around to prevent infinite resize
                return;
            }
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                let evt;
                if (typeof (Event) === 'function') {
                    // modern browsers
                    evt = new Event('resize');
                } else {
                    // for IE and other old browsers
                    // causes deprecation warning on modern browsers
                    evt = window.document.createEvent('UIEvents');
                    evt.initUIEvent('resize', true, false, window, 0);
                }
                evt.huntEvent = true;
                window.dispatchEvent(evt);
            }, 250);
        });

        if (this.props.filters.length) {
            this.loadActions(this.props.filters);
        }

        const detectspecialkeys = (e, keyDown) => {
            if (e.keyCode === 17) {
                if (this.state.copyMode !== keyDown) {
                    this.setState({ copyMode: keyDown });
                }
            }
        };

        document.onkeydown = (e) => detectspecialkeys(e, true);
        document.onkeyup = (e) => detectspecialkeys(e, false);
    }

    componentDidUpdate(prevProps) {
        // An adjustment of the panels height is needed for their first proper placement
        if (this.panelsBooted === 'yes' && !this.panelsAdjusted) {
            this.panelsAdjusted = true;
            this.adjustPanelsHeight();
        }

        if (typeof this.props.systemSettings !== 'undefined') {
            this.qFilter = this.generateQFilter();
            this.storedMicroLayout = store.get('dashboardMicroLayout');
            this.storedMacroLayout = store.get('dashboardMacroLayout');
            // Initial booting of panels were moved here instead of componentDidMount, because of the undefined systemSettings in componentDidMount
            if (this.panelsBooted === 'no') {
                this.bootPanels();
            } else if (!this.filters.length) {
                this.filters = JSON.stringify(this.props.filters);
            } else if (this.panelsBooted !== 'booting' && (this.filters !== JSON.stringify(this.props.filters) || JSON.stringify(prevProps.filtersWithAlert) !== JSON.stringify(this.props.filtersWithAlert) || prevProps.from_date !== this.props.from_date)) {
                this.filters = JSON.stringify(this.props.filters);
                this.resetPanelHeights();
                this.bootPanels();
            }
        }
    }

    getBlockFromLS = (panel, block, breakPoint) => {
        let result = {};
        if (typeof this.storedMicroLayout !== 'undefined' && typeof this.storedMicroLayout[panel] !== 'undefined' && typeof this.storedMicroLayout[panel][breakPoint] !== 'undefined') {
            result = find(this.storedMicroLayout[panel][breakPoint], { i: block });
        }
        return result;
    };

    getPanelFromLS = (panel) => {
        let result = {};
        if (typeof this.storedMacroLayout !== 'undefined' && typeof this.storedMacroLayout[panel] !== 'undefined') {
            result = find(this.storedMacroLayout, { i: panel });
        }
        return result;
    };

    generateQFilter = () => {
        let qfilter = buildQFilter(this.props.filtersWithAlert, this.props.systemSettings);
        if (!qfilter) {
            qfilter = '';
        }
        return qfilter;
    }

    /* default panel properties should be extended with the stored equivalent into the local storage */
    extendDefaultPanels = () => {
        const storedMacroLayout = store.get('dashboardMacroLayout');
        return Object.assign({}, ...Object.keys(dashboard.sections).map((k) => {
            const storedPanel = find(storedMacroLayout, { i: k });
            if (typeof storedPanel === 'undefined') {
                return {
                    [k]: {
                        ...dashboard.sections[k]
                    }
                }
            }

            return {
                [k]: {
                    ...dashboard.sections[k],
                    dimensions: {
                        ...dashboard.sections[k].dimensions,
                        y: storedPanel.y
                    }
                }
            }
        }));
    }

    /* reset panel to it's initial state - no data into blocks and the default height for the panel with empty blocks */
    resetPanelHeights = () => {
        const reset = Object.assign({}, ...Object.keys(this.state.dashboard).map((k) => ({
            [k]: {
                ...this.state.dashboard[k],
                items: [
                    ...this.state.dashboard[k].items.map((z, i) => ({
                        ...z,
                        data: null,
                        dimensions: {
                            ...dashboard.sections[k].items[i].dimensions
                        }
                    }))
                ],
                dimensions: {
                    ...this.state.dashboard[k].dimensions,
                    h: dashboard.sections[k].dimensions.h,
                    minH: dashboard.sections[k].dimensions.minH,
                }
            }
        })));

        this.setState({
            ...this.state,
            dashboard: reset
        })
    }

    bootPanels = () => {
        this.panelsLoaded = 0;
        this.panelsBooted = 'booting';
        this.panelState.dashboard = { ...this.state.dashboard };
        this.resetPanelHeights();
        map(this.state.load, (panel) => this.bootPanel(panel));
    }

    bootPanel = (panel) => {
        // Count the number of the blocks
        let blocksLoaded = 0;
        let newHeight = 0;
        const array = this.state.dashboard[panel].items;
        for (let j = 0; j < array.length; j += 1) {
            const block = array[j];
            axios.get(`${config.API_URL + config.ES_BASE_PATH
            }field_stats/?field=${block.i
            }&from_date=${this.props.from_date
            }&page_size=5${this.qFilter}`)
            .then((json) => {
                // Validation of the data property
                if (typeof json.data === 'undefined' || json.data === null) { json.data = []; }

                // When all of the blocks from a single panel are loaded, then mark the panel as loaded
                blocksLoaded += 1;
                if (blocksLoaded === this.state.dashboard[panel].items.length) {
                    this.panelsLoaded += 1;
                }

                const height = Math.ceil(((json.data.length * dashboard.block.defaultItemHeight) + dashboard.block.defaultHeadHeight) / 13);
                const panelHeight = (json.data.length) ? 10 + (json.data.length * dashboard.block.defaultItemHeight) + dashboard.block.defaultHeadHeight + dashboard.panel.defaultHeadHeight : dashboard.panel.defaultHeadHeight;
                const isPanelLoaded = (!this.state.dashboard[panel].items.find((itm) => itm.data !== null && itm.data.length === 0));

                const items = this.panelState.dashboard[panel].items.map((el) => {
                    if (el.i === block.i) {
                        const data = (json.data.length) ? json.data : [];

                        if (data) {
                            for (let idx = 0; idx < data.length; idx += 1) {
                                if (!data[idx].key) {
                                    data[idx].key = 'Unknown';
                                }
                            }
                        }

                        let extended = {
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
                        if (el.i === block.i) {
                            extended = { ...extended, data };
                        }
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
                    });
                }
            });
        }
    };

    itemCopyModeOnClick = (event, itemPath, key, parentElem) => {
        if (event.ctrlKey) {
            this.setState({ copiedItem: itemPath });
            setTimeout(() => {
                this.setState({ copiedItem: '' });
            }, 1500);
            copyTextToClipboard(key, parentElem);
        }
    }

    onMouseMove = (event, itemPath) => {
        if (this.state.hoveredItem !== itemPath) {
            this.setState({ hoveredItem: itemPath });
        }
        if (this.state.copyMode !== event.ctrlKey) {
            this.setState({ copyMode: event.ctrlKey });
        }
    }

    onMouseLeave = (event, itemPath) => {
        if (this.state.hoveredItem === itemPath) {
            this.setState({ hoveredItem: null });
        }
    }

    createElement = (block) => {
        const url = `${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=${block.i}&from_date=${this.props.from_date}&page_size=30${this.qFilter}`;
        return (
            <div key={block.i}
                style={{ background: 'white' }}
            >
                {this.props.children}
                <h3 className={`hunt-stat-title ${(this.state.editMode) ? 'dashboard-editable-mode' : ''}`} data-toggle="tooltip" title={block.title}>{block.title}</h3>
                {block.data !== null && block.data.length === 5 && <DropdownKebab id={`more-${this.props.item}`} pullRight>
                    <MenuItem onClick={() => this.loadMore(block, url)} data-toggle="modal">Load more results</MenuItem>
                </DropdownKebab>}
                <div className="hunt-stat-body">
                    <ListGroup>
                        {block.data === null && <Spinner loading />}
                        {block.data !== null && block.data.map((item) => {
                            const itemPath = `${block.title}-${block.i}-${item.key}`;
                            let classes = 'dashboard-list-item';
                            let clickHandler = null;
                            classes += (this.state.copiedItem === itemPath) ? ' copied' : '';

                            if (this.state.copyMode && this.state.hoveredItem === itemPath) {
                                // Only set clickHandler during copy mode to let click events reach the magnifiers in EventValue
                                // otherwise hover and click on magnifiers breaks on Firefox
                                clickHandler = (event) => this.itemCopyModeOnClick(event, itemPath, item.key);
                                classes += ' copy-mode';
                            }

                            return <ListGroupItem
                                key={item.key}
                                onClick={clickHandler}
                                onMouseMove={(event) => this.onMouseMove(event, itemPath)}
                                onMouseLeave={(event) => this.onMouseLeave(event, itemPath)}
                                className={classes}
                            >
                                <ErrorHandler>
                                    <EventValue field={block.i}
                                        value={item.key}
                                        magnifiers={!this.state.copyMode || this.state.hoveredItem !== itemPath}
                                        right_info={<Badge>{item.doc_count}</Badge>}
                                    />
                                </ErrorHandler>
                            </ListGroupItem>;
                        })}
                    </ListGroup>
                </div>
            </div>
        );
    };

    getMacroLayouts = () => this.state.load.map((panel) => ({
        ...this.state.dashboard[panel].dimensions, isDraggable: this.state.editMode, i: panel.toString()
    }));

    getMicroLayouts = (panel, bp) => {
        const tallestBlock = this.makeHeightsEqual(panel, bp);
        return this.state.dashboard[panel].items.map((item) => ({
            ...item.dimensions[bp],
            h: tallestBlock,
            maxH: tallestBlock,
            minH: tallestBlock,
            i: item.i.toString()
        }));
    }

    makeHeightsEqual = (panel, bp) => {
        let h = 0;
        const blocks = this.state.dashboard[panel].items;
        for (let i = 0; i < blocks.length; i += 1) {
            h = (h > blocks[i].dimensions[bp].h) ? h : blocks[i].dimensions[bp].h;
        }
        return h;
    }

    resetDashboard = (e) => {
        e.preventDefault();
        // eslint-disable-next-line no-alert
        const ask = window.confirm('Confirm reset positions of the dashboard panels?');
        if (ask) {
            store.remove('dashboardMacroLayout');
            store.remove('dashboardMicroLayout');
            window.location.reload();
        }
    };

    switchEditMode = (e) => {
        this.setState({ editMode: !this.state.editMode });
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
        for (let i = 0; i < panelsArray.length; i += 1) {
            const panelBodySize = this.getPanelBodySize(panelsArray[i]);
            const panelRealSize = (parseInt(panelBodySize, 10) + parseInt(dashboard.panel.defaultHeadHeight, 10));
            if (this.getPanelSize(panelsArray[i]) !== panelRealSize) {
                stateChanged = true;
                tmpState = {
                    ...tmpState,
                    dashboard: {
                        ...tmpState.dashboard,
                        [panelsArray[i]]: {
                            ...tmpState.dashboard[panelsArray[i]],
                            dimensions: {
                                ...tmpState.dashboard[panelsArray[i]].dimensions,
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

    getPanelSize = (panel) => parseInt(document.querySelector(`#panel-${panel}`).style.height.replace('px', ''), 10);

    getPanelBodySize = (panel) => parseInt(document.querySelector(`#panel-${panel} div.react-grid-layout`).style.height.replace('px', ''), 10);

    onChangeMacroLayout = (macroLayout) => {
        store.set('dashboardMacroLayout', macroLayout);
        let tmpState = this.state.dashboard;
        for (let k = 0; k < macroLayout.length; k += 1) {
            tmpState = {
                ...tmpState,
                [macroLayout[k].i]: {
                    ...tmpState[macroLayout[k].i],
                    dimensions: macroLayout[k]
                }
            };
        }
        this.setState({ dashboard: tmpState });
    };

    onDragStartMicro = () => {
        this.panelAutoresize = true;
    };

    onResizeStartMicro =() => {
        this.panelAutoresize = true;
    };

    onChangeMicroLayout = (panel, microLayout) => {
        if (this.panelAutoresize) {
            if (this.state.breakPoint !== null) {
                const ls = store.get('dashboardMicroLayout') || {
                    [panel]: {
                        lg: {}, md: {}, sm: {}, xs: {}
                    }
                };
                store.set('dashboardMicroLayout', {
                    ...ls,
                    [panel]: {
                        ...ls[panel],
                        [this.state.breakPoint]: microLayout
                    }
                });

                let obj = this.state;
                for (let j = 0; j < microLayout.length; j += 1) {
                    obj = {
                        ...obj,
                        dashboard: {
                            ...this.state.dashboard,
                            [panel]: {
                                ...this.state.dashboard[panel],
                                items: this.state.dashboard[panel].items.map((vv) => {
                                    const innerItem = { ...vv };
                                    if (microLayout[j].i === vv.i) {
                                        innerItem.dimensions[this.state.breakPoint] = microLayout[j];
                                    }
                                    return Object.assign({}, vv, innerItem);
                                }),
                            }
                        }
                    };
                }

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

    onBreakPointChange = (breakpoint) => {
        if (this.state.breakPoint !== breakpoint) {
            this.breakPointChanged = true;
            this.setState({ breakPoint: breakpoint });
        }
    };

    loadMore = (item, url) => {
        axios.get(url)
        .then((json) => {
            const data = (json.data.length) ? json.data : null;

            if (data) {
                for (let idx = 0; idx < data.length; idx += 1) {
                    if (!data[idx].key) {
                        data[idx].key = 'Unknown';
                    }
                }
            }

            this.setState({ moreModal: item, moreResults: json.data });
        });
    }

    hideMoreModal = () => this.setState({ ...this.state, moreModal: null });

    onChangeChartTarget = (chartTarget) => {
        this.setState({
            chartTarget
        });
    }

    render() {
        return (
            <div className="HuntList">
                <ErrorHandler>
                    <HuntFilter
                        ActiveFilters={this.props.filters}
                        config={this.props.rules_list}
                        ActiveSort={this.props.rules_list.sort}
                        UpdateFilter={this.UpdateFilter}
                        UpdateSort={this.UpdateSort}
                        setViewType={this.setViewType}
                        filterFields={this.state.rulesFilters}
                        sort_config={undefined}
                        displayToggle={undefined}
                        actionsButtons={this.actionsButtons}
                        queryType={['filter', 'filter_host_id']}
                        page={this.props.page}
                        filterType={sections.GLOBAL}
                    />
                </ErrorHandler>

                <div className="row">
                    <div className="col-lg-10 col-md-9 col-sm-12 col-xs-12" style={{ paddingRight: '0px' }}>
                        <HuntTimeline style={{ marginTop: '15px' }} from_date={this.props.from_date} chartTarget={this.state.chartTarget} filters={this.props.filtersWithAlert} systemSettings={this.props.systemSettings} />
                    </div>
                    <div className="col-lg-2 col-md-3 col-sm-12 col-xs-12" style={{ paddingLeft: '0px' }}>
                        <HuntTrend from_date={this.props.from_date} filters={this.props.filtersWithAlert} />
                        {typeof this.state.chartTarget !== 'undefined' && (process.env.REACT_APP_HAS_TAG === '1' || process.env.NODE_ENV === 'development') && <div style={{ position: 'absolute', zIndex: 10, top: 0, right: '30px' }}>
                            <DropdownKebab id={'more-actions'} pullRight><MenuItem onClick={() => this.onChangeChartTarget(!this.state.chartTarget)} data-toggle="modal">Switch timeline by probes/tags</MenuItem></DropdownKebab>
                        </div>}
                    </div>
                </div>
                <div className="row drag-and-drop-container">
                    <div className="col-md-12">

                        <div className="pull-right">
                            <a href={'#edit'} onClick={this.switchEditMode}>{(this.state.editMode) ? 'switch off edit mode' : 'edit'}</a>
                            <span> • </span> {/* ignore_utf8_check: 8226 */}
                            <a href={'#reset'} onClick={this.resetDashboard}>reset</a>
                        </div>
                        <div className="clearfix" />

                        { this.panelsBooted !== 'no' && <ResponsiveReactGridLayout
                            margin={[0, 0.01]}
                            compactType={'vertical'}
                            isResizable={false}
                            rowHeight={1}
                            draggableHandle={'.hunt-row-title'}
                            cols={{
                                lg: 1,
                                md: 1,
                                sm: 1,
                                xs: 1,
                                xxs: 1
                            }}
                            layouts={{
                                lg: this.getMacroLayouts(),
                                md: this.getMacroLayouts(),
                                sm: this.getMacroLayouts(),
                                xs: this.getMacroLayouts()
                            }}
                            onLayoutChange={this.onChangeMacroLayout}
                        >
                            { this.panelsBooted !== 'no' && this.state.load.map((panel) => (
                                <div className="hunt-row" key={panel} id={`panel-${panel}`}>
                                    <h2 className={`hunt-row-title ${(this.state.editMode) ? 'dashboard-editable-mode' : ''}`}>{this.state.dashboard[panel].title}</h2>
                                    <ResponsiveReactGridLayout
                                        margin={[5, 5]}
                                        compactType={'vertical'}
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
                                        isDraggable={this.state.editMode}
                                        isResizable={this.state.editMode}
                                        rowHeight={10}
                                        draggableHandle={'.hunt-stat-title'}
                                        cols={{
                                            lg: 32, md: 24, sm: 16, xs: 8, xxs: 4
                                        }}
                                    >
                                        { this.state.dashboard[panel].items.map((block) => this.createElement(block)) }
                                    </ResponsiveReactGridLayout>
                                </div>)
                            )}
                        </ResponsiveReactGridLayout>}
                    </div>
                </div>
                <ErrorHandler>
                    <RuleToggleModal show={this.state.action.view} action={this.state.action.type} config={this.props.rules_list} filters={this.props.filters} close={this.closeAction} rulesets={this.state.rulesets} />
                </ErrorHandler>
                <Modal show={!(this.state.moreModal === null)} onHide={() => { this.hideMoreModal(); }}>

                    <Modal.Header>More results <Modal.CloseButton closeText={'Close'} onClick={() => { this.hideMoreModal(); }} /> </Modal.Header>
                    <Modal.Body>
                        <div className="hunt-stat-body" id="more-result-modal">
                            <ListGroup>
                                {this.state.moreModal && this.state.moreResults.map((item) => {
                                    const itemPath = `modal-${this.state.moreModal.title}-${this.state.moreModal.i}-${item.key}`;
                                    let classes = 'dashboard-list-item';
                                    let clickHandler = null;
                                    classes += (this.state.copiedItem === itemPath) ? ' copied' : '';

                                    if (this.state.copyMode && this.state.hoveredItem === itemPath) {
                                        // Only set clickHandler during copy mode to let click events reach the magnifiers in EventValue
                                        // otherwise hover and click on magnifiers breaks on Firefox
                                        const moreResultModal = document.getElementById('more-result-modal');
                                        clickHandler = (event) => this.itemCopyModeOnClick(event, itemPath, item.key, moreResultModal);
                                        classes += ' copy-mode';
                                    }

                                    return <ListGroupItem
                                        key={item.key}
                                        onClick={clickHandler}
                                        onMouseMove={(event) => this.onMouseMove(event, itemPath)}
                                        onMouseLeave={(event) => this.onMouseLeave(event, itemPath)}
                                        className={classes}
                                    >
                                        {this.state.moreModal && <ErrorHandler>
                                            <EventValue field={this.state.moreModal.i}
                                                value={item.key}
                                                magnifiers={!this.state.copyMode || this.state.hoveredItem !== itemPath}
                                                right_info={<Badge>{item.doc_count}</Badge>}
                                            />
                                        </ErrorHandler>}
                                    </ListGroupItem>;
                                })}
                            </ListGroup>
                        </div>
                    </Modal.Body>
                </Modal>
            </div>
        );
    }
}

HuntDashboard.propTypes = {
    systemSettings: PropTypes.any,
    filters: PropTypes.any,
    from_date: PropTypes.any,
    children: PropTypes.any,
    item: PropTypes.any,
    rules_list: PropTypes.any,
    updateListState: PropTypes.any,
    page: PropTypes.any,
    filtersWithAlert: PropTypes.array,
}

const mapStateToProps = createStructuredSelector({
    filters: makeSelectGlobalFilters(),
    filtersWithAlert: makeSelectGlobalFilters(true),
    alertTag: makeSelectAlertTag(),
});

export default connect(mapStateToProps)(HuntDashboard);
