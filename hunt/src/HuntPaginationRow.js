import React from 'react';
import PropTypes from 'prop-types';
import { PaginationRow, PAGINATION_VIEW_TYPES } from 'patternfly-react';

export default class HuntPaginationRow extends React.Component {
    constructor(props) {
        super(props);
        this.updatePagination = this.updatePagination.bind(this);
        this.onPageInput = this.onPageInput.bind(this);
    }

    updatePagination = (pagin) => {
        const pagination = {
            ...this.props.itemsList,
            pagination: {
                ...this.props.itemsList.pagination,
                ...pagin
            }
        };

        const pageCount = Math.ceil(this.props.itemsCount / pagination.perPage);
        pagination.page = Math.min(pagination.page, pageCount);
        this.props.onPaginationChange(pagination);
    }

    onPageInput = (e) => {
        const val = parseInt(e.target.value, 10);
        if (val > 0) {
            this.updatePagination({ page: val });
        }
    }

    render() {
        const { pagination } = this.props.itemsList;
        const pageCount = Math.ceil(this.props.itemsCount / pagination.perPage);
        return (
            <PaginationRow pageSizeDropUp
                viewType={this.props.viewType}
                pageInputValue={pagination.page}
                pagination={pagination}
                amountOfPages={pageCount}
                itemCount={this.props.itemsCount - 1}
                itemsStart={(pagination.page - 1) * pagination.perPage}
                itemsEnd={Math.min((pagination.page * pagination.perPage) - 1, this.props.itemsCount - 1)}
                onPageInput={this.onPageInput}
                onPerPageSelect={(e) => this.updatePagination({ perPage: e })}
                onPreviousPage={() => this.updatePagination({ page: pagination.page - 1 })}
                onNextPage={() => this.updatePagination({ page: pagination.page + 1 })}
                onFirstPage={() => this.updatePagination({ page: 1 })}
                onLastPage={() => this.updatePagination({ page: pageCount })}
            />
        );
    }
}
HuntPaginationRow.propTypes = {
    onPaginationChange: PropTypes.func.isRequired,
    viewType: PropTypes.oneOf(PAGINATION_VIEW_TYPES).isRequired,
    itemsCount: PropTypes.number.isRequired,
    itemsList: PropTypes.object.isRequired,
};
