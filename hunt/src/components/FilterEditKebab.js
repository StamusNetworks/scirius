import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { DropdownKebab, MenuItem } from 'patternfly-react';
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import FilterToggleModal from '../FilterToggleModal';
import ErrorHandler from './Error';
import FilterSetSave from './FilterSetSaveModal';
import { loadFilterSets } from './FilterSets/store';

class FilterEditKebab extends React.Component {
    constructor(props) {
        super(props);
        this.displayToggle = this.displayToggle.bind(this);
        this.hideToggle = this.hideToggle.bind(this);
        this.state = { toggle: { show: false, action: 'delete' }, filterSets: { showModal: false, page: '', shared: false, name: '' }, errors: undefined, user: undefined };
        this.closeAction = this.closeAction.bind(this);
        this.convertActionToFilters = this.convertActionToFilters.bind(this);
        this.saveActionToFilterSet = this.saveActionToFilterSet.bind(this);
        this.handleFieldChange = this.handleFieldChange.bind(this);
        this.handleComboChange = this.handleComboChange.bind(this);
        this.handleDescriptionChange = this.handleDescriptionChange.bind(this);
        this.setSharedFilter = this.setSharedFilter.bind(this);
        this.submitActionToFilterSet = this.submitActionToFilterSet.bind(this);
    }

    componentDidMount() {
        axios.get(`${config.API_URL}${config.USER_PATH}current_user/`)
        .then((currentUser) => {
            this.setState({ user: currentUser.data });
        });
    }

    setSharedFilter(e) {
        this.setState({ filterSets: { showModal: true, shared: e.target.checked, page: this.state.filterSets.page, name: this.state.filterSets.name, description: this.state.filterSets.description } });
    }

    closeActionToFilterSet = () => {
        this.setState({ filterSets: { showModal: false, shared: false, page: 'DASHBOARDS', name: '', errors: undefined, description: '' } });
    }

    generateFilterSet = () => {
        const self = this.props.data;
        const tags = { untagged: true, relevant: true, informational: true };
        const keys = Object.keys(tags);

        if (self.action === 'tag' || self.action === 'tagkeep') {
            for (let idx = 0; idx < keys.length; idx += 1) {
                tags[keys[idx]] = keys[idx] === self.options.tag;
            }
        }

        const filters = process.env.REACT_APP_HAS_TAG === '1' ? [{ id: 'alert.tag', value: tags }] : [];
        for (let idx = 0; idx < this.props.data.filter_defs.length; idx += 1) {
            const val = Number(this.props.data.filter_defs[idx].value) ? Number(this.props.data.filter_defs[idx].value) : this.props.data.filter_defs[idx].value;
            const filter = { id: this.props.data.filter_defs[idx].key,
                key: this.props.data.filter_defs[idx].key,
                label: `${this.props.data.filter_defs[idx].key}: ${this.props.data.filter_defs[idx].value}`,
                value: val,
                negated: this.props.data.filter_defs[idx].operator !== 'equal',
                fullString: this.props.data.filter_defs[idx].full_string }

            filters.push(filter);
        }
        return filters;
    }

    displayToggle(action) {
        this.setState({ toggle: { show: true, action } });
    }

    hideToggle() {
        this.setState({ toggle: { show: false, action: this.state.toggle.action } });
    }

    closeAction() {
        this.setState({ toggle: { show: false, action: 'delete' } });
    }

    saveActionToFilterSet() {
        this.setState({ filterSets: { showModal: true, page: 'DASHBOARDS', shared: false, name: '', description: '' } });
    }

    convertActionToFilters() {
        const filters = this.generateFilterSet();
        this.props.updateIDSFilterState(filters);
    }

    handleComboChange(event) {
        this.setState({ filterSets: { showModal: true, shared: this.state.filterSets.shared, page: event.target.value, name: this.state.filterSets.name, description: this.state.filterSets.description } });
    }

    handleFieldChange(event) {
        this.setState({ filterSets: { showModal: true, shared: this.state.filterSets.shared, page: this.state.filterSets.page, name: event.target.value, description: this.state.filterSets.description } });
    }

    handleDescriptionChange(event) {
        this.setState({ filterSets: { showModal: true, shared: this.state.filterSets.shared, page: this.state.filterSets.page, name: this.state.filterSets.name, description: event.target.value } });
    }

    submitActionToFilterSet() {
        const filters = this.generateFilterSet();

        axios.post(config.API_URL + config.HUNT_FILTER_SETS, { name: this.state.filterSets.name, page: this.state.filterSets.page, content: filters, share: this.state.filterSets.shared, description: this.state.filterSets.description })
        .then(() => {
            this.props.loadFilterSets();
            this.closeActionToFilterSet();
            this.setState({ errors: undefined });
        })
        .catch((error) => {
            let errors = error.response.data;

            if (error.response.status === 403) {
                const noRights = this.state.user.is_active && !this.state.user.is_staff && !this.state.user.is_superuser && this.state.filterSets.shared;
                if (noRights) {
                    errors = { permission: ['Insufficient permissions. "Shared" is not allowed.'] };
                }
            }
            this.setState({ errors });
        });
    }

    render() {
        const noRights = this.state.user !== undefined && this.state.user.is_active && !this.state.user.is_staff && !this.state.user.is_superuser;
        return (
            <React.Fragment>

                <FilterSetSave
                    title={'Create new Filter Set From Action'}
                    showModal={this.state.filterSets.showModal}
                    close={this.closeActionToFilterSet}
                    errors={this.state.errors}
                    handleDescriptionChange={this.handleDescriptionChange}
                    handleComboChange={this.handleComboChange}
                    handleFieldChange={this.handleFieldChange}
                    setSharedFilter={this.setSharedFilter}
                    submit={this.submitActionToFilterSet}
                    noRights={noRights}
                />

                <DropdownKebab id="filterActions" pullRight>
                    {this.props.data.index !== 0 && <MenuItem onClick={() => { this.displayToggle('movetop'); }}>
                        Send Action to top
                    </MenuItem>}
                    <MenuItem onClick={() => { this.displayToggle('move'); }}>
                        Move Action
                    </MenuItem>
                    <MenuItem onClick={() => { this.displayToggle('movebottom'); }}>
                        Send Action to bottom
                    </MenuItem>
                    <MenuItem divider />
                    <MenuItem onClick={() => { this.displayToggle('delete'); }}>
                        Delete Action
                    </MenuItem>
                    <MenuItem divider />
                    <MenuItem onClick={() => { this.convertActionToFilters(); }}>
                        Convert Action to Filters
                    </MenuItem>
                    <MenuItem onClick={() => { this.saveActionToFilterSet(); }}>
                        Save Action as Filter set
                    </MenuItem>
                </DropdownKebab>
                <ErrorHandler>
                    <FilterToggleModal show={this.state.toggle.show} action={this.state.toggle.action} data={this.props.data} close={this.closeAction} last_index={this.props.last_index} needUpdate={this.props.needUpdate} />
                </ErrorHandler>
            </React.Fragment>
        );
    }
}
FilterEditKebab.propTypes = {
    data: PropTypes.any,
    last_index: PropTypes.any,
    needUpdate: PropTypes.any,
    updateIDSFilterState: PropTypes.any,
    loadFilterSets: PropTypes.func,
};

const mapDispatchToProps = {
    loadFilterSets,
};

export default connect(null, mapDispatchToProps)(FilterEditKebab);
