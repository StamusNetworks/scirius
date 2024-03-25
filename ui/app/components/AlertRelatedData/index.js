import React from 'react';

import { Table } from 'antd';
import moment from 'moment';
import PropTypes from 'prop-types';
import ReactJson from 'react-json-view';

import columns from 'ui/components/AlertRelatedData/columns';
import constants from 'ui/constants';

const AlertRelatedData = ({ type, data }) => {
  const tableColumns = columns[type] ?? [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(constants.DATE_TIME_FORMAT) },
    { title: 'Event Type', dataIndex: ['rawJson', 'event_type'] },
  ];

  return (
    <React.Fragment key="json-related">
      {data?.length === 0 && <strong>No related events detected</strong>}
      {data?.length > 0 && (
        <Table
          columns={tableColumns}
          dataSource={data}
          expandable={{
            expandRowByClick: true,
            expandedRowRender: record => (
              <ReactJson
                name={false}
                src={record.rawJson}
                displayDataTypes={false}
                displayObjectSize={false}
                collapseStringsAfterLength={150}
                collapsed={false}
              />
            ),
            rowExpandable: () => true,
          }}
        />
      )}
    </React.Fragment>
  );
};
AlertRelatedData.propTypes = {
  type: PropTypes.string.isRequired,
  data: PropTypes.array,
};

export default AlertRelatedData;
