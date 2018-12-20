import React from 'react';
import PropTypes from 'prop-types';
import { PaginationRow, PAGINATION_VIEW_TYPES } from 'patternfly-react';

export default class HuntPaginationRow extends React.Component {
    constructor(props) {
        super(props);
        this.onPageInput = this.onPageInput.bind(this);
        this.onPerPageSelect = this.onPerPageSelect.bind(this);
    }

    onPageInput = (e) => {
        const val = parseInt(e.target.value, 10);
        if (val > 0) {
            const newPaginationState = Object.assign({}, this.props.pagination);
            newPaginationState.page = val;
            this.props.onPaginationChange(newPaginationState);
        }
    }

    onPerPageSelect = (eventKey) => {
        const newPaginationState = Object.assign({}, this.props.pagination);
        newPaginationState.perPage = eventKey;
        this.props.onPaginationChange(newPaginationState);
    }

    render() {
        const {
            viewType,
            pageInputValue,
            amountOfPages,
            pageSizeDropUp,
            itemCount,
            itemsStart,
            itemsEnd,
            onFirstPage,
            onPreviousPage,
            onNextPage,
            onLastPage
        } = this.props;

        return (
            <PaginationRow
                viewType={viewType}
                pageInputValue={pageInputValue}
                pagination={this.props.pagination}
                amountOfPages={amountOfPages}
                pageSizeDropUp={pageSizeDropUp}
                itemCount={itemCount}
                itemsStart={itemsStart}
                itemsEnd={itemsEnd}
                onPerPageSelect={this.onPerPageSelect}
                onFirstPage={onFirstPage}
                onPreviousPage={onPreviousPage}
                onPageInput={this.onPageInput}
                onNextPage={onNextPage}
                onLastPage={onLastPage}
            />
        );
    }
}
HuntPaginationRow.propTypes = {
    pagination: PropTypes.any,
    onPaginationChange: PropTypes.func,
};

function noop() {

}

HuntPaginationRow.propTypes = {
    viewType: PropTypes.oneOf(PAGINATION_VIEW_TYPES).isRequired,
    pageInputValue: PropTypes.number.isRequired,
    amountOfPages: PropTypes.number.isRequired,
    pageSizeDropUp: PropTypes.bool,
    itemCount: PropTypes.number.isRequired,
    itemsStart: PropTypes.number.isRequired,
    itemsEnd: PropTypes.number.isRequired,
    onFirstPage: PropTypes.func,
    onPreviousPage: PropTypes.func,
    onNextPage: PropTypes.func,
    onLastPage: PropTypes.func
};

HuntPaginationRow.defaultProps = {
    pageSizeDropUp: true,
    onFirstPage: noop,
    onPreviousPage: noop,
    onNextPage: noop,
    onLastPage: noop
};
