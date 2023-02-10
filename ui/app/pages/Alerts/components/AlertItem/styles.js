import styled from 'styled-components';

export const DlHorizontal = styled.dl`
  & .dl-item {
    display: grid;
    grid-template-columns: 1fr 1fr;
  }
  & dt {
    justify-self: end;
  }
  & dd {
    overflow: hidden;
    -o-text-overflow: ellipsis;
    text-overflow: ellipsis;
    margin-left: 20px;
    margin-bottom: 0;
  }
`;

export const Numbers = styled.div`
  display: grid;
  grid-template-columns: 1fr min-content;
  grid-gap: 5px;
  align-items: center;
`;

export const Pre = styled.pre`
  max-height: 215px;
  overflow-y: auto;
  white-space: pre-wrap;
  background: #f0f2f5;
  padding: 5px 10px;
  margin-bottom: 0;
`;

export const Warning = styled.div`
  text-align: center;
  color: red;
  padding-bottom: 10px;
`;

export const Container = styled.div`
  display: grid;
  grid-template-columns: 3fr 2fr 2fr 0.5fr 0.5fr;
  justify-items: center;
  grid-gap: 20px;
`;

export const TabPaneResponsive = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  grid-gap: 10px;
  padding-bottom: 10px;
`;
