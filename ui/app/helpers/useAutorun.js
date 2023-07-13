import { useEffect, useCallback, useMemo } from 'react';
import { autorun } from 'mobx';
import { useStore } from 'ui/mobx/RootStoreProvider';

function useAutorun(callback, dependencies) {
  const { commonStore, tenantStore } = useStore();

  const effectDeps = useMemo(() => dependencies?.filter(dep => !['ids', 'date', 'tenant'].includes(dep)) || [], [dependencies]);
  const hasAny = !!dependencies?.some(dep => ['ids', 'date', 'tenant'].includes(dep));

  const cb = useCallback(
    ({ ...globalDeps }) => {
      callback(globalDeps);
    },
    [callback, ...effectDeps],
  );

  return useEffect(
    () =>
      autorun(() => {
        try {
          let trigger = false;
          const params = {};
          if (hasAny) {
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
          }
          if (trigger || !hasAny || dependencies.length === 0) {
            cb(params);
          }
          // eslint-disable-next-line no-empty
        } catch (e) {}
      }),
    [...effectDeps],
  );
}

export default useAutorun;
