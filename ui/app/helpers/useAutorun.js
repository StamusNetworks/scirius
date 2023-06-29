import { useEffect, useCallback } from 'react';
import { autorun } from 'mobx';
import { useStore } from 'ui/mobx/RootStoreProvider';

function useAutorun(callback, dependencies = ['ids', 'date', 'tenant'], others = []) {
  const { commonStore, tenantStore } = useStore();

  const cb = useCallback(
    ({ ...globalDeps }) => {
      callback(globalDeps);
    },
    [callback, ...others],
  );

  return useEffect(
    () =>
      autorun(() => {
        try {
          let trigger = false;
          const params = {};
          if (dependencies.includes('ids')) {
            params.ids = commonStore.filtersWithAlert;
            trigger = true;
          }
          if (dependencies.includes('date')) {
            params.startDate = commonStore.startDate;
            params.endDate = commonStore.endDate;
            trigger = true;
          }
          if (dependencies.includes('tenant')) {
            params.tenant = tenantStore?.tenant;
            trigger = true;
          }
          if (trigger || dependencies.length === 0) {
            cb(params);
          }
          // eslint-disable-next-line no-empty
        } catch (e) {}
      }),
    [...others],
  );
}

export default useAutorun;
