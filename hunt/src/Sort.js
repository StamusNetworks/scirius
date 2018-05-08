import React from 'react';
import { Sort } from 'patternfly-react';

export const RuleSortFields = [
  {
    id: 'created',
    title: 'Created',
    isNumeric: true,
    defaultAsc: false,
  },
  {
    id: 'alerts',
    title: 'Alerts',
    isNumeric: true,
    defaultAsc: false,
  },
  {
    id: 'msg',
    title: 'Message',
    isNumeric: false,
    defaultAsc: true,
  },
  {
    id: 'updated',
    title: 'Updated',
    isNumeric: true,
    defaultAsc: false,
  }
];

export class RuleSort extends React.Component {
    state = {
      currentSortType: RuleSortFields[0],
      isSortNumeric: RuleSortFields[0].isNumeric,
      isSortAscending: false
    };

  updateCurrentSortType = sortType => {
    const { currentSortType } = this.state;
    if (currentSortType !== sortType) {
      this.setState({
        currentSortType: sortType,
        isSortNumeric: sortType.isNumeric,
        isSortAscending: sortType.defaultAsc
      });
      this.props.UpdateSort({id: sortType['id'], asc: sortType['defaultAsc']});
    }
  }

  toggleCurrentSortDirection = () => {
    this.props.UpdateSort({id: this.state.currentSortType['id'], asc: !this.state.isSortAscending});
    this.setState(prevState => {
      return { isSortAscending: !prevState.isSortAscending };
    });
  }

  render() {
    const { currentSortType, isSortNumeric, isSortAscending } = this.state;

    return (
        <Sort>
          <Sort.TypeSelector
            sortTypes={RuleSortFields}
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
