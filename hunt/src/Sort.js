import React from 'react';
import { Sort } from 'patternfly-react';

export class HuntSort extends React.Component {
  constructor(props) {
    super(props);
    var sort_type;
    for (var i = 0; i<this.props.config.length; i++){
         if (this.props.ActiveSort.id === this.props.config[i].id) {
            sort_type = this.props.config[i];
            break;
         }
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
