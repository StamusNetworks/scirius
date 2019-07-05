import React from 'react';
import PropTypes from 'prop-types';
import { Icon, Spinner } from 'patternfly-react';
import RuleEditKebab from './components/RuleEditKebab';
import SciriusChart from './components/SciriusChart';
import ErrorHandler from './components/Error';

const RuleCard = (props) => {
    const { category } = props.data;
    const source = props.sources[category.source];
    let catTooltip = category.name;
    if (source && source.name) {
        catTooltip = `${source.name}: ${category.name}`;
    }
    let imported;
    if (!props.data.created) {
        [imported] = props.data.imported_date.split('T');
    }

    const kebabConfig = { rule: props.data };
    return (
        <div className="col-xs-6 col-sm-4 col-md-4">
            <div className="card-pf rule-card">
                <div className="card-pf-heading">
                    <h2 className="card-pf-title truncate-overflow" data-toggle="tooltip" title={props.data.msg}>{props.data.msg}</h2>
                    <RuleEditKebab key={`kebab-${props.data.sid}`} config={kebabConfig} rulesets={props.rulesets} />
                </div>
                <div className="card-pf-body">
                    <div className="container-fluid">
                        <div className="row">
                            <div className="col-md-5 truncate-overflow" data-toggle="tooltip" title={catTooltip}>Cat: {category.name}</div>
                            <div className="col-md-4">
                                {props.data.created && <p>Created: {props.data.created}</p>}
                                {!props.data.created && <p>Imported: {imported}</p>}
                            </div>
                            <div className="col-md-3">Alerts
                                <Spinner loading={props.data.hits === undefined} size="xs">
                                    <span className="badge">{props.data.hits}</span>
                                </Spinner>
                            </div>
                        </div>
                    </div>
                    <Spinner loading={props.data.hits === undefined} size="xs">
                        {props.data.timeline && <div className="chart-pf-sparkline">
                            <ErrorHandler>
                                <SciriusChart data={props.data.timeline}
                                    axis={{
                                        x: { show: false, min: props.from_date },
                                        y: { show: false }
                                    }}
                                    legend={{ show: false }}
                                    size={{ height: 60 }}
                                    point={{ show: false }}
                                />
                            </ErrorHandler>
                        </div>}
                        {!props.data.timeline && <div className="no-sparkline">
                            <p>No alert</p>
                        </div>}
                    </Spinner>
                    <div>
                        SID: <strong>{props.data.sid}</strong>
                        <span className="pull-right">
                            <a onClick={() => { props.switchPage(props.data); }} style={{ cursor: 'pointer' }}>
                                <Icon type="fa" name="search-plus" />
                            </a>
                        </span>
                    </div>
                </div>
            </div>
        </div>
    );
}

RuleCard.propTypes = {
    data: PropTypes.any,
    sources: PropTypes.any,
    from_date: PropTypes.any,
    switchPage: PropTypes.any,
    rulesets: PropTypes.any,
};

export default RuleCard;
