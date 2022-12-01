import React from 'react';
import PropTypes from 'prop-types';
import { Pagination } from 'antd';

export default class HuntPaginationRow extends React.Component {
  constructor(props) {
    super(props);
    this.updatePagination = this.updatePagination.bind(this);
    this.onChange = this.onChange.bind(this);
  }

  updatePagination = pagin => {
    const pagination = {
      ...this.props.itemsList,
      pagination: {
        ...this.props.itemsList.pagination,
        ...pagin,
      },
    };

    const pageCount = Math.ceil(this.props.itemsCount / pagination.perPage);
    pagination.page = Math.min(pagination.page, pageCount);
    this.props.onPaginationChange(pagination);
  };

  onChange = (page, pageSize) => {
    const val = parseInt(page, 10);
    if (val > 0) {
      this.updatePagination({ page: val, perPage: pageSize });
    }
  };

  getCurrentPage = () => {
    const { page, perPage } = this.props.itemsList.pagination;
    // show page 1 when we dont have data for the currently selected page
    // (for example when we are currently at page 300 and then filter is applied and the result is 1 page but we still stay on page 300)
    if (page > 1 && Math.ceil(this.props.itemsCount / perPage) < page) this.updatePagination({ page: 1, perPage });
    return page;
  };

  render() {
    return (
      <React.Fragment>
        <Pagination
          current={this.getCurrentPage()}
          pageSize={this.props.itemsList.pagination.perPage}
          total={this.props.itemsCount - 1}
          showSizeChanger
          onChange={this.onChange}
          style={{ display: 'flex', justifyContent: 'end', marginTop: '10px' }}
        />
      </React.Fragment>
    );
  }
}
HuntPaginationRow.propTypes = {
  onPaginationChange: PropTypes.func.isRequired,
  itemsCount: PropTypes.number.isRequired,
  itemsList: PropTypes.object.isRequired,
};
