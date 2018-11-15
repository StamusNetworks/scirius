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
import { Sort } from 'patternfly-react';

export class HuntSort extends React.Component {
    constructor(props) {
        super(props);
        var sort_type;
        for (var i = 0; i < this.props.config.length; i++) {
            if (this.props.ActiveSort.id === this.props.config[i].id) {
                sort_type = this.props.config[i];
                break;
            }
        }
        if (sort_type === undefined) {
            sort_type = this.props.config[0]
        }
        this.state = {
            currentSortType: sort_type,
            isSortNumeric: sort_type.isNumeric,
            isSortAscending: this.props.ActiveSort.asc
        };
    }

    updateCurrentSortType = sortType => {
        const { currentSortType } = this.state;
        if (currentSortType !== sortType) {
            this.setState({
                currentSortType: sortType,
                isSortNumeric: sortType.isNumeric,
                isSortAscending: sortType.defaultAsc
            });
            this.props.UpdateSort({ id: sortType['id'], asc: sortType['defaultAsc'] });
        }
    }

    toggleCurrentSortDirection = () => {
        this.props.UpdateSort({ id: this.state.currentSortType['id'], asc: !this.state.isSortAscending });
        this.setState(prevState => {
            return { isSortAscending: !prevState.isSortAscending };
        });
    }

    render() {
        const { currentSortType, isSortNumeric, isSortAscending } = this.state;

        return (
            <Sort>
                <Sort.TypeSelector
                    sortTypes={this.props.config}
                    currentSortType={currentSortType}
                    onSortTypeSelected={this.updateCurrentSortType}
                />
                <Sort.DirectionSelector
                    isNumeric={isSortNumeric}
                    isAscending={isSortAscending}
                    onClick={() => this.toggleCurrentSortDirection()}
                />
            </Sort>
        );
    }
}
