/**
 * Documentation here https://github.com/SanCoder-Q/flat-combine-reducers
 */
const defaultOptions = {
  mergePrevState: true
};

function partitionArgs(args) {
  const lastArgs = args[args.length - 1];

  if (typeof lastArgs !== 'function') {
    return [args.slice(0, args.length - 1), lastArgs];
  }

  return [args];
}

export default function flatCombineReducers() {
  // eslint-disable-next-line prefer-rest-params
  const [inputReducers, inputOptions] = partitionArgs([...arguments]);

  const options = Object.assign({}, defaultOptions, inputOptions);

  const reducers = options.mergePrevState ? [x=>x].concat(inputReducers) : inputReducers;

  return (prevState, action) => reducers.reduce((state, reducer) =>
    Object.assign({}, state, reducer(prevState, action)), {}
  );
}
