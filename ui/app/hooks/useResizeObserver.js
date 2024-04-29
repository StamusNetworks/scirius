import { useState, useCallback } from 'react';

import ResizeObserver from 'resize-observer-polyfill';

const useResizeObserver = () => {
  const [width, setWidth] = useState();

  const handleResize = useCallback(entries => {
    if (!Array.isArray(entries)) {
      return;
    }

    const entry = entries[0];
    setWidth(entry.contentRect.width);
  });

  const callback = useCallback(ref => {
    if (!ref) {
      return;
    }

    let RO = new ResizeObserver(entries => handleResize(entries));
    RO.observe(ref);

    // eslint-disable-next-line consistent-return
    return () => {
      RO.disconnect();
      RO = null;
    };
  }, []);

  return [callback, width];
};

export default useResizeObserver;
