import { Button } from 'antd';
import PropTypes from 'prop-types';
import React from 'react';
import { DownloadOutlined } from '@ant-design/icons';

import { makeCsv, formatTable } from './helper';

/**
 * Download CSV takes columns, rows definitions and a filename to create a CSV file to download
 * @param {Array} cols - Cols have to contain a title and dataIndex
 * @param {Array} rows - Rows have to contain the same keys as the dataIndex in the cols, values have to be string | number | undefined
 * @param {String} filename - Name of the file to download (without extension eg: 'file')
 * @returns {Button} - Button to download the CSV
 */

export const DownloadCSV = ({ cols, rows, filename }) => (
  <Button type="button" icon={<DownloadOutlined />} onClick={() => makeCsv(formatTable(cols, rows), `${filename}.csv`)}>
    Export
  </Button>
);

DownloadCSV.propTypes = {
  cols: PropTypes.arrayOf(
    PropTypes.shape({
      title: PropTypes.string.isRequired,
      dataIndex: PropTypes.string.isRequired,
    }),
  ).isRequired,
  rows: PropTypes.array.isRequired,
  filename: PropTypes.string.isRequired,
};
