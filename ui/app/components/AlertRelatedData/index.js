import React from 'react';
import { Table } from 'antd';
import ReactJson from 'react-json-view';
import PropTypes from 'prop-types';
import columns from 'ui/components/AlertRelatedData/columns';

const AlertRelatedData = ({ type, data }) => (
  <React.Fragment key="json-related">
    {data?.length === 0 && <strong>No related events detected</strong>}
    {data?.length > 0 && (
      <Table
        columns={columns[type]}
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
AlertRelatedData.propTypes = {
  type: PropTypes.string.isRequired,
  data: PropTypes.array,
};

export default AlertRelatedData;
