import styled from 'styled-components';

export const PolicyContainer = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  grid-gap: 10px;
  padding-bottom: 10px;
`;

export const ActionItemContainer = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, 200px);
  grid-gap: 20px;
  justify-items: center;
  &:not(:last-child) {
    margin-bottom: 20px;
  }
`;

export const Actionitem = styled.div`
  display: grid;
  grid-gap: 5px;
  justify-items: center;
`;

export const ActionSubItemOne = styled.div`
  display: grid;
  grid-template-columns: min-content 1fr;
  grid-column-gap: 10px;
  align-items: center;
  font-size: 14px;
`;

export const ActionSubItemTwo = styled.div`
  display: grid;
  grid-template-columns: repeat(2, max-content);
  grid-gap: 15px;
`;

export const ActionSubItemTwoItem = styled.div`
  display: grid;
  grid-template-columns: repeat(2, max-content);
  column-gap: 5px;
  align-items: center;
`;

export const DescriptionItem = styled.div`
  padding: 0 10px;
`;

export const FiltersCell = styled.div`
  display: flex;
  flex-direction: row;
`;

export const Parameter = styled.div`
  padding: 0 10px;
`;
