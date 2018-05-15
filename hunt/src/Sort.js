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
    id: 'hits',
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
  constructor(props) {
    super(props);
    var sort_type;
    for (var i = 0; i<RuleSortFields.length; i++){
         if (this.props.ActiveSort.id === RuleSortFields[i].id) {
            sort_type = RuleSortFields[i];
            break;
         }
    }
    this.state = {
      currentSortType: sort_type,
      isSortNumeric: sort_type.isNumeric,
      isSortAscending: sort_type.asc
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
