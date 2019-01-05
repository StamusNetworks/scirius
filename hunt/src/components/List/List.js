import React from 'react';
import PropTypes from 'prop-types';
import { ListView } from 'patternfly-react';
import CardView from '../CardView';

const List = (props) => {
    const ItemComponent = (props.type === 'list') ? props.component.list : props.component.card;
    const ListComponent = (props.type === 'list') ? ListView : CardView;
    return <React.Fragment>
        <ListComponent>{props.items.map((rule) => <ItemComponent key={rule.sid} data={rule} {...props.itemProps} />)}</ListComponent>
    </React.Fragment>
}

List.propTypes = {
    type: PropTypes.any,
    items: PropTypes.any,
    component: PropTypes.any,
    itemProps: PropTypes.any,
};

export default List;
