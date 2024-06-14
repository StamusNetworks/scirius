import { useStore } from 'ui/mobx/RootStoreProvider';

const useFilterParams = () => {
  const { commonStore } = useStore();
  let fromDate = commonStore.startDate;
  let toDate = commonStore.endDate;

  if (commonStore.relativeType !== 'Auto') {
    if (commonStore.relativeType !== 'All') {
      fromDate *= 1000;
    }
    toDate *= 1000;
  }
  return `from_date=${fromDate}&to_date=${toDate}`;
};

export default useFilterParams;
