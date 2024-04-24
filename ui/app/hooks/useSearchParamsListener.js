import { useEffect } from 'react';

import { useDispatch } from 'react-redux';
import { useHistory } from 'react-router-dom';

import constants from 'ui/containers/App/constants';

function useSearchParamsListener() {
  const history = useHistory();
  const dispatch = useDispatch();

  const triggerDispatch = () => dispatch({ type: constants.LOCATION_CHANGE });

  useEffect(() => {
    const unlisten = history.listen(triggerDispatch);
    triggerDispatch();
    return () => {
      unlisten();
    };
  }, [history]);
}

export default useSearchParamsListener;
