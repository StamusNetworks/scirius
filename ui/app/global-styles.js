import { createGlobalStyle } from 'styled-components';

const GlobalStyle = createGlobalStyle`
  .ant-breadcrumb {
    display: flex;
    align-items: center;
    font-size: 10px;
    color: #818181;
    border-bottom: 1px solid #ccc;
  }
  .ant-table-row:hover > td {
    background: #f0f2f5 !important;
  }

  *, *::before, *::after {
    box-sizing: border-box;
    font-smooth: antialiased;
    padding: 0;
    margin: 0;
  }
`;

export default GlobalStyle;
