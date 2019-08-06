import React from 'react';
import PropTypes from 'prop-types';
import { PAGE_STATE } from 'hunt_common/constants';
import SignaturesPage from '../../containers/SignaturesPage';
import SourcePage from '../../components/SourcePage';
import RulesetPage from '../../components/RuleSetPage';
import DashboardPage from '../../containers/DashboardPage';
import HistoryPage from '../../containers/HistoryPage';
import AlertsPage from '../../containers/AlertsPage';
import ActionsPage from '../../containers/ActionsPage';

const DisplayPage = (props) => {
    let displayedPage = null;
    switch (props.page) {
        case PAGE_STATE.rules_list:
        default:
            displayedPage = (<SignaturesPage
                systemSettings={props.systemSettings}
                rules_list={props.rules_list}
                filters={props.idsFilters}
                from_date={props.from_date}
                switchPage={props.switchPage}
                updateListState={props.updateRuleListState}
                updateFilterState={props.updateIDSFilterState}
                page={props.page}
            />);
            break;
        case PAGE_STATE.source:
            displayedPage = <SourcePage systemSettings={props.systemSettings} source={props.item} from_date={props.from_date} page={props.page} />;
            break;
        case PAGE_STATE.ruleset:
            displayedPage = <RulesetPage systemSettings={props.systemSettings} ruleset={props.item} from_date={props.from_date} page={props.page} />;
            break;
        case PAGE_STATE.dashboards:
            // FIXME remove or change updateRuleListState
            displayedPage = (<DashboardPage
                systemSettings={props.systemSettings}
                rules_list={props.rules_list}
                filters={props.idsFilters}
                from_date={props.from_date}
                switchPage={props.switchPage}
                updateListState={props.updateRuleListState}
                updateFilterState={props.updateIDSFilterState}
                needReload={props.needReload}
                page={props.page}
            />);
            break;
        case PAGE_STATE.history:
            displayedPage = (<HistoryPage
                systemSettings={props.systemSettings}
                rules_list={props.history_list}
                filters={props.historyFilters}
                from_date={props.from_date}
                updateListState={props.updateHistoryListState}
                switchPage={props.switchPage}
                updateFilterState={props.updateHistoryFilterState}
                page={props.page}
            />);
            break;
        case PAGE_STATE.alerts_list:
            displayedPage = (<AlertsPage
                systemSettings={props.systemSettings}
                rules_list={props.alerts_list}
                filters={props.idsFilters}
                from_date={props.from_date}
                updateListState={props.updateAlertListState}
                switchPage={props.switchPage}
                updateFilterState={props.updateIDSFilterState}
                page={props.page}
            />);
            break;
        case PAGE_STATE.filters_list:
            displayedPage = (<ActionsPage
                systemSettings={props.systemSettings}
                rules_list={props.filters_list}
                filters={props.filters_filters}
                from_date={props.from_date}
                updateListState={props.updateFilterListState}
                switchPage={props.switchPage}
                updateFilterState={props.updateFiltersFilterState}
                updateIDSFilterState={props.updateIDSFilterState}
            />);
            break;
    }

    return displayedPage;
}

DisplayPage.propTypes = {
    page: PropTypes.any,
    systemSettings: PropTypes.any,
    rules_list: PropTypes.any,
    idsFilters: PropTypes.any,
    from_date: PropTypes.any,
    switchPage: PropTypes.any,
    updateRuleListState: PropTypes.any,
    updateIDSFilterState: PropTypes.any,
    item: PropTypes.any,
    needReload: PropTypes.any,
    history_list: PropTypes.any,
    historyFilters: PropTypes.any,
    updateHistoryListState: PropTypes.any,
    updateHistoryFilterState: PropTypes.any,
    alerts_list: PropTypes.any,
    updateAlertListState: PropTypes.any,
    filters_list: PropTypes.any,
    filters_filters: PropTypes.any,
    updateFilterListState: PropTypes.any,
    updateFiltersFilterState: PropTypes.any,
    updateHostListState: PropTypes.any,
}
export default DisplayPage;
