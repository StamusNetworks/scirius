import React from 'react';
import PropTypes from 'prop-types';

const EventIPPastries = props => {
  const baseUrl = 'https://pastebin.com/';
  return (
    <div>
      <h4>Pastries info</h4>
      <dl>
        {props.data.map(item => {
          if (item['@type'] === 'pastebin') {
            return (
              <React.Fragment>
                <dt>
                  <a href={`${baseUrl}item.key`} target="_blank">{`${baseUrl}item.key`}</a>
                </dt>
                <dd>{`${item.seen_date}`}</dd>
              </React.Fragment>
            );
          }
          return null;
        })}
      </dl>
    </div>
  );
};

EventIPPastries.propTypes = {
  data: PropTypes.any,
};

export default EventIPPastries;
