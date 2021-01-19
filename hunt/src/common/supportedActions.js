export const supportedActions = ['threshold'];

export function setDefaultOptions() {
  let options = {};
  switch (this.props.action) {
    case 'threshold':
      options = {
        type: 'both',
        count: 1,
        seconds: 60,
        track: 'by_src',
      };
      break;
    default:
      break;
  }
  this.setState({ options });
}
