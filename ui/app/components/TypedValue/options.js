import React from 'react';

import { CopyOutlined, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import { message } from 'antd';

import copyTextToClipboard from 'ui/helpers/copyTextToClipboard';

const CETypedOptions = {
  COPY_TO_CLIPBOARD: value => ({
    key: 'copyTextToClipboard',
    label: (
      <div
        onClick={() => {
          copyTextToClipboard(value);
          message.success({
            duration: 1,
            content: 'Copied!',
          });
        }}
      >
        <CopyOutlined /> <span>Copy text to clipboard</span>
      </div>
    ),
  }), // Copy text to clipboard
  FILTER_ON_IP: (displayValue, onClick) => ({
    key: 'typedValueIP2',
    label: (
      <div onClick={onClick}>
        <ZoomInOutlined /> <span>Filter on IP: {displayValue}</span>
      </div>
    ),
  }), // Filter on IP: 0.0.0.0
  NEGATED_FILTER_ON_IP: (displayValue, onClick) => ({
    key: 'typedValueIP3',
    label: (
      <div onClick={onClick}>
        <ZoomOutOutlined /> <span>Negated filter on IP: {displayValue}</span>
      </div>
    ),
  }), // Negated filter on IP: 0.0.0.0
};

export default CETypedOptions;
