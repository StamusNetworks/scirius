/* eslint-disable global-require */
import { PAGE_STATE } from 'hunt_common/constants';

const VerticalNavItems = [{
    title: 'Dashboard',
    iconClass: 'fa fa-tachometer',
    def: PAGE_STATE.dashboards,
    className: null,
}, {
    title: 'Signatures',
    iconClass: 'glyphicon glyphicon-eye-open',
    def: PAGE_STATE.rules_list,
    className: null,
}, {
    title: 'Alerts',
    iconClass: 'pficon pficon-security',
    def: PAGE_STATE.alerts_list,
}, {
    title: 'Actions',
    iconClass: 'glyphicon glyphicon-filter',
    def: PAGE_STATE.filters_list,
}, {
    title: 'History',
    iconClass: 'glyphicon glyphicon-list',
    def: PAGE_STATE.history,
}];

export default VerticalNavItems;
