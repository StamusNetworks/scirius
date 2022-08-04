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

  render() {
    return (
      <React.Fragment>
        <Pagination
          defaultCurrent={1}
          total={this.props.itemsCount - 1}
          showSizeChanger={false}
          showQuickJumper={false}
          onChange={this.onChange}
          hideOnSinglePage
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
