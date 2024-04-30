import styled from 'styled-components';

const NotStyle = `
  background: #9c9c9c;
  cursor: default;
  display: flex;
  align-items: center;
  padding-left: 7px;
  padding-right: 7px;
`;

export const FilterContainer = styled.li`
  display: flex !important;
  padding: 0 !important;
  align-items: center;
  text-decoration: ${p => (p.suspended ? 'line-through' : '')};
  background-color: ${p => (p.disabled ? '#c2c2c2' : '#005792')};

  color: #ffffff;
  height: 22px;
  line-height: 11px;
`;

export const FilterLabels = styled.li`
  display: flex;
  height: 20px;
  gap: 1px;
  margin-left: 1px;
`;

export const FilterContent = styled.div`
  display: flex !important;
  gap: 10px;
  justify-content: space-between;
  align-items: center;
  border-radius: 0;
  box-sizing: border-box;
  font-family: 'Open Sans', Helvetica, Arial, sans-serif;
  font-size: 11px;
  list-style: none outside none;
  margin: 1px;
  text-align: center;
  vertical-align: baseline;
  white-space: normal;
`;

export const FilterLabel = styled.span`
  box-sizing: border-box;
  font-family: 'Open Sans', Helvetica, Arial, sans-serif;
  font-size: 11px;
  list-style: none outside none;
  cursor: default;
  padding-left: ${p => (!p?.hasIcon ? '5px' : '0')};
`;

export const FilterText = styled.div`
  display: flex;
  align-items: center;
`;

export const FilterIconsContainer = styled.div`
  display: flex;
`;

export const SilverLabelAsterisk = styled.div`
  ${NotStyle};
  font-size: 22px;
  padding-top: 7px;
  font-family: Serif, serif;
`;

export const SilverLabelNot = styled.div`
  ${NotStyle};
  font-size: 11px;
  font-weight: bold;
`;
