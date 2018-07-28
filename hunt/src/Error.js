import React from 'react';

export class HuntRestError extends React.Component {
    render() {
        if (this.props.errors === undefined) {
                return(null);
        } else {
                return(
             <div>
             {Object.keys(this.props.errors).map( field => {
                    return(
                      <div key={field}>
                       {this.props.errors[field].map( error => {
			    if (typeof(error) === 'object') {
				return(<div key={1} className="alert alert-danger">{field}: {JSON.stringify(error)}</div>);
			    } else {
                            	return(<div key={error} className="alert alert-danger">{field}: {error}</div>)
			    }
                    })
                    }
                      </div>
                    );
             })
             }
             </div>
             )
        }
    }
}
