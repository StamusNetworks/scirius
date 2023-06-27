import { useStore } from 'ui/mobx/RootStoreProvider';

const useFilterParams = () => {
  const { commonStore } = useStore();
  return `from_date=${commonStore.startDate}&to_date=${commonStore.endDate}`;
};

export default useFilterParams;
