import { useHistory } from 'react-router-dom';

export function useCustomHistory() {
  const history = useHistory();

  return {
    ...history,
  };
}
