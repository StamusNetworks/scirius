import { useEffect, useCallback } from 'react';
import { autorun } from 'mobx';
import { useStore } from 'ui/mobx/RootStoreProvider';

function useAutorun(callback, dependencies = ['ids', 'date', 'tenant']) {
  const { commonStore, tenantStore } = useStore();

  const cb = useCallback(
    ({ ...globalDeps }) => {
      callback(globalDeps);
    },
    [callback],
  );

  return useEffect(() => {
    return autorun(() => {
      try {
        let trigger = false;
        const params = {};
        if (dependencies.includes('ids')) {
          params.ids = commonStore.ids;
          trigger = true;
        }
        if (dependencies.includes('date')) {
          // console.log('GLOBALS', dependencies);
          params.startDate = commonStore.startDate;
          params.endDate = commonStore.endDate;
          trigger = true;
        }
        if (dependencies.includes('tenant')) {
          params.endDate = tenantStore?.tenant;
          trigger = true;
        }
        if (trigger) {
          cb(params);
        }
        // eslint-disable-next-line no-empty
      } catch (e) {}
    });
  }, []);
}

export default useAutorun;
