import { useEffect, useState } from 'react';
import endpoints from 'ui/config/endpoints';
import { api } from 'ui/mobx/api';
import FilterValueType from 'ui/maps/FilterValueType';
import { FilterCategory } from 'ui/maps/Filters';

const useHistoryFilters = () => {
  const [result, setResult] = useState([]);
  useEffect(() => {
    (async () => {
      const response = await api.get(endpoints.HISTORY_FILTERS.url);
      if (response.ok) {
        const { data = {} } = response;
        const { action_type_list: actionTypeList = [] } = data;
        const items = Object.keys(actionTypeList).map(c => ({
          value: c,
          label: actionTypeList[c],
        }));
        setResult(items);
      }
    })();
  }, []);

  return [
    {
      value: 'username',
      label: 'User',
      category: FilterCategory.HISTORY,
    },
    {
      value: 'comment',
      label: 'Comment',
      category: FilterCategory.HISTORY,
    },
    {
      value: 'action_type',
      label: 'Action Type',
      valueType: FilterValueType.SELECT,
      children: result,
      category: FilterCategory.HISTORY,
    },
    {
      value: 'client_ip',
      label: 'Client IP',
      category: FilterCategory.HISTORY,
    },
  ];
};

export default useHistoryFilters;
