import React from 'react';

import { List as ListView } from 'antd';
import PropTypes from 'prop-types';

import CardView from 'ui/components/CardView';
import ErrorHandler from 'ui/components/Error';

const List = props => {
  const ItemComponent = props.type === 'list' ? props.component.list : props.component.card;
  const ListComponent = props.type === 'list' ? ListView : CardView;

  return (
    <ListComponent
      size="small"
      header={null}
      footer={null}
      dataSource={props.items}
      renderItem={rule => (
        <ErrorHandler key={Math.random()}>
          <ItemComponent key={rule.sid} data={rule} {...props.itemProps} />
        </ErrorHandler>
      )}
    />
  );
};

List.propTypes = {
  type: PropTypes.any,
  items: PropTypes.any,
  component: PropTypes.any,
  itemProps: PropTypes.any,
};

export default List;
