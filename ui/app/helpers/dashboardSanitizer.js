import { createRef } from 'react';

const dashboardSanitizer = data => {
  /**
   * Convert empty keys to 'Unknown' values
   */
  const blockIds = Object.keys(data);
  if (blockIds.length > 0) {
    blockIds.forEach(blockId => {
      for (let idx = 0; idx < data[blockId].length; idx += 1) {
        data.nodeRef = createRef(null);
        if (!data[blockId][idx].key) {
          data[blockId][idx].key = 'Unknown';
        }
      }
    });
  }
  return data;
};

export default dashboardSanitizer;
