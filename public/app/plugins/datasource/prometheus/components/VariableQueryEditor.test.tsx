import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';
import { selectOptionInTest } from 'test/helpers/selectOptionInTest';

import { PrometheusDatasource } from '../datasource';
import { PromVariableQuery, PromVariableQueryType, StandardPromVariableQuery } from '../types';

import { PromVariableQueryEditor, Props, variableMigration } from './VariableQueryEditor';

const refId = 'PrometheusVariableQueryEditor-VariableQuery';

describe('PromVariableQueryEditor', () => {
  let props: Props;

  test('Migrates from standard variable support to custom variable query', () => {
    const query: StandardPromVariableQuery = {
      query: 'label_names()',
      refId: 'StandardVariableQuery',
    };

    const migration: PromVariableQuery = variableMigration(query);

    const expected: PromVariableQuery = {
      qryType: PromVariableQueryType.LabelNames,
      refId: 'PrometheusDatasource-VariableQuery',
    };

    expect(migration).toEqual(expected);
  });

  test('Allows for use of variables to interpolate label names in the label values query type.', () => {
    const query: StandardPromVariableQuery = {
      query: 'label_values($label_name)',
      refId: 'StandardVariableQuery',
    };

    const migration: PromVariableQuery = variableMigration(query);

    const expected: PromVariableQuery = {
      qryType: PromVariableQueryType.LabelValues,
      label: '$label_name',
      refId: 'PrometheusDatasource-VariableQuery',
    };

    expect(migration).toEqual(expected);
  });

  test('Migrates from jsonnet grafana as code variable to custom variable query', () => {
    const query = 'label_names()';

    const migration: PromVariableQuery = variableMigration(query);

    const expected: PromVariableQuery = {
      qryType: PromVariableQueryType.LabelNames,
      refId: 'PrometheusDatasource-VariableQuery',
    };

    expect(migration).toEqual(expected);
  });

  beforeEach(() => {
    props = {
      datasource: {
        hasLabelsMatchAPISupport: () => 1,
        languageProvider: {
          start: () => Promise.resolve([]),
          syntax: () => {},
          getLabelKeys: () => [],
          metrics: [],
          metricsMetadata: {},
          getLabelValues: jest.fn().mockImplementation(() => ['that']),
          fetchSeriesLabelsMatch: jest.fn().mockImplementation(() => Promise.resolve({ those: 'those' })),
        },
        getInitHints: () => [],
        getDebounceTimeInMilliseconds: jest.fn(),
        getTagKeys: jest.fn().mockImplementation(() => Promise.resolve(['this'])),
        getVariables: jest.fn().mockImplementation(() => []),
        metricFindQuery: jest.fn().mockImplementation(() => Promise.resolve(['that'])),
      } as unknown as PrometheusDatasource,
      query: {
        refId: 'test',
        query: 'label_names()',
      },
      onRunQuery: () => {},
      onChange: () => {},
      history: [],
    };
  });

  test('Displays a group of function options', async () => {
    render(<PromVariableQueryEditor {...props} />);

    const select = screen.getByLabelText('Query type').parentElement!;
    await userEvent.click(select);

    await waitFor(() => expect(screen.getAllByText('Label names')).toHaveLength(2));
    await waitFor(() => expect(screen.getByText('Label values')).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText('Metrics')).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText('Query result')).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText('Series query')).toBeInTheDocument());
  });

  test('Calls onChange for label_names() query', async () => {
    const onChange = jest.fn();

    props.query = {
      refId: 'test',
      query: '',
    };

    render(<PromVariableQueryEditor {...props} onChange={onChange} />);

    await selectOptionInTest(screen.getByLabelText('Query type'), 'Label names');

    expect(onChange).toHaveBeenCalledWith({
      query: 'label_names()',
      labelFilters: [],
      refId,
    });
  });

  test('Does not call onChange for other queries', async () => {
    const onChange = jest.fn();

    render(<PromVariableQueryEditor {...props} onChange={onChange} />);

    await selectOptionInTest(screen.getByLabelText('Query type'), 'Label values');
    await selectOptionInTest(screen.getByLabelText('Query type'), 'Metrics');
    await selectOptionInTest(screen.getByLabelText('Query type'), 'Query result');
    await selectOptionInTest(screen.getByLabelText('Query type'), 'Series query');

    expect(onChange).not.toHaveBeenCalled();
  });

  test('Calls onChange for metrics() after input', async () => {
    const onChange = jest.fn();

    props.query = {
      refId: 'test',
      query: 'label_names()',
    };

    render(<PromVariableQueryEditor {...props} onChange={onChange} />);

    await selectOptionInTest(screen.getByLabelText('Query type'), 'Metrics');
    const metricInput = screen.getByLabelText('Metric selector');
    await userEvent.type(metricInput, 'a');

    waitFor(() =>
      expect(onChange).toHaveBeenCalledWith({
        query: 'metrics(a)',
        labelFilters: [],
        refId,
      })
    );
  });

  test('Calls onChange for label_values() after selecting label', async () => {
    const onChange = jest.fn();

    props.query = {
      refId: 'test',
      query: 'label_names()',
    };

    render(<PromVariableQueryEditor {...props} onChange={onChange} />);

    await selectOptionInTest(screen.getByLabelText('Query type'), 'Label values');
    const labelSelect = screen.getByLabelText('label-select');
    await userEvent.type(labelSelect, 'this');
    await selectOptionInTest(labelSelect, 'this');

    waitFor(() =>
      expect(onChange).toHaveBeenCalledWith({
        query: 'label_values(this)',
        labelFilters: [],
        refId,
      })
    );
  });

  test('Calls onChange for label_values() after selecting metric', async () => {
    const onChange = jest.fn();

    props.query = {
      refId: 'test',
      query: 'label_names()',
    };

    render(<PromVariableQueryEditor {...props} onChange={onChange} />);

    await selectOptionInTest(screen.getByLabelText('Query type'), 'Label values');
    const labelSelect = screen.getByLabelText('label-select');
    await userEvent.type(labelSelect, 'this');
    await selectOptionInTest(labelSelect, 'this');

    const metricSelect = screen.getByLabelText('Metric');
    await userEvent.type(metricSelect, 'that');
    await selectOptionInTest(metricSelect, 'that');

    waitFor(() =>
      expect(onChange).toHaveBeenCalledWith({
        query: 'label_values(that,this)',
        labelFilters: [],
        refId,
      })
    );
  });

  test('Calls onChange for query_result() with argument onBlur', async () => {
    const onChange = jest.fn();

    props.query = {
      refId: 'test',
      query: 'query_result(a)',
    };

    render(<PromVariableQueryEditor {...props} onChange={onChange} />);

    const labelSelect = screen.getByLabelText('Prometheus Query');
    await userEvent.click(labelSelect);
    const functionSelect = screen.getByLabelText('Query type').parentElement!;
    await userEvent.click(functionSelect);

    expect(onChange).toHaveBeenCalledWith({
      query: 'query_result(a)',
      labelFilters: [],
      refId,
    });
  });

  test('Calls onChange for Match[] series with argument onBlur', async () => {
    const onChange = jest.fn();

    props.query = {
      refId: 'test',
      query: '{a: "example"}',
    };

    render(<PromVariableQueryEditor {...props} onChange={onChange} />);

    const labelSelect = screen.getByLabelText('Series Query');
    await userEvent.click(labelSelect);
    const functionSelect = screen.getByLabelText('Query type').parentElement!;
    await userEvent.click(functionSelect);

    expect(onChange).toHaveBeenCalledWith({
      query: '{a: "example"}',
      labelFilters: [],
      refId,
    });
  });
});
