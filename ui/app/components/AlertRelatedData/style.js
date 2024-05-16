import { Table as AntTable } from 'antd';
import styled from 'styled-components';

export const Table = styled(AntTable)`
  .ant-table {
    margin: 0 !important;
  }
  td {
    font-size: 0.75rem;
  }
  .pretty-json-container {
    font-size: 1rem;
  }
`;

export const BreakAnywhere = styled.div`
  word-break: break-all;
  white-space: pre-wrap;
`;
