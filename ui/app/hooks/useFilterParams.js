import { useStore } from 'ui/mobx/RootStoreProvider';

const useFilterParams = () => {
  const { commonStore } = useStore();
  return `from_date=${commonStore.startDate * 1000}&to_date=${commonStore.endDate * 1000}`;
};

export default useFilterParams;
