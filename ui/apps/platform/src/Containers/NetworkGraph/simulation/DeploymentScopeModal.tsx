import React, { useState } from 'react';
import {
    Bullseye,
    Button,
    Modal,
    Pagination,
    Spinner,
    Toolbar,
    ToolbarContent,
    ToolbarItem,
} from '@patternfly/react-core';
import { ExclamationCircleIcon } from '@patternfly/react-icons';
import { Table, Thead, Tr, Th, Tbody, Td } from '@patternfly/react-table';
import { gql, useQuery } from '@apollo/client';

import EmptyStateTemplate from 'Components/EmptyStateTemplate';
import useTableSort from 'hooks/useTableSort';
import { getPaginationParams, getRequestQueryStringForSearchFilter } from 'utils/searchUtils';

import { useSearchFilter } from '../NetworkGraphURLStateContext';

const deploymentQuery = gql`
    query getDeploymentsForPolicyGeneration($query: String!, $pagination: Pagination!) {
        deployments(query: $query, pagination: $pagination) {
            id
            name
            namespace
        }
    }
`;

const sortFields = ['Deployment', 'Namespace'];
const defaultSortOption = { field: 'Deployment', direction: 'asc' } as const;

export type DeploymentScopeModalProps = {
    scopeDeploymentCount: number;
    isOpen: boolean;
    onClose: () => void;
};

function DeploymentScopeModal({
    scopeDeploymentCount,
    isOpen,
    onClose,
}: DeploymentScopeModalProps) {
    const { sortOption, getSortParams } = useTableSort({ sortFields, defaultSortOption });
    const [page, setPage] = useState(1);
    const [perPage, setPerPage] = useState(20);

    const { searchFilter } = useSearchFilter();

    const options = {
        skip: !isOpen,
        variables: {
            query: getRequestQueryStringForSearchFilter(searchFilter),
            pagination: getPaginationParams({ page, perPage, sortOption }),
        },
    };
    const { data, previousData, loading, error } = useQuery<
        {
            deployments: {
                id: string;
                name: string;
                namespace: string;
            }[];
        },
        { query: string }
    >(deploymentQuery, options);

    const deployments = data?.deployments ?? previousData?.deployments ?? [];

    return (
        <Modal
            isOpen={isOpen}
            title="Selected deployment scope"
            variant="small"
            onClose={onClose}
            actions={[
                <Button key="close" onClick={onClose}>
                    Close
                </Button>,
            ]}
        >
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem variant="pagination" align={{ default: 'alignRight' }}>
                        <Pagination
                            isCompact
                            itemCount={scopeDeploymentCount}
                            page={page}
                            perPage={perPage}
                            onSetPage={(_, newPage) => setPage(newPage)}
                            onPerPageSelect={(_, newPerPage) => {
                                setPerPage(newPerPage);
                            }}
                        />
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>
            {error && (
                <Bullseye>
                    <EmptyStateTemplate
                        title="There was an error loading deployments"
                        headingLevel="h2"
                        icon={ExclamationCircleIcon}
                        iconClassName="pf-v5-u-danger-color-100"
                    >
                        {error.message}
                    </EmptyStateTemplate>
                </Bullseye>
            )}
            {loading && deployments.length === 0 && (
                <Bullseye>
                    <Spinner aria-label="Loading deployments" />
                </Bullseye>
            )}
            {!error && (
                <Table variant="compact">
                    <Thead noWrap>
                        <Tr>
                            <Th width={50} sort={getSortParams('Deployment')}>
                                Deployment
                            </Th>
                            <Th width={50} sort={getSortParams('Namespace')}>
                                Namespace
                            </Th>
                        </Tr>
                    </Thead>
                    <Tbody>
                        {deployments.map(({ id, name, namespace }) => (
                            <Tr key={id}>
                                <Td dataLabel="Deployment">{name}</Td>
                                <Td dataLabel="Namespace">{namespace}</Td>
                            </Tr>
                        ))}
                    </Tbody>
                </Table>
            )}
        </Modal>
    );
}

export default DeploymentScopeModal;
