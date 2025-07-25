import React from 'react';
import { Link } from 'react-router-dom-v5-compat';
import { Flex, Title, Truncate } from '@patternfly/react-core';
import { Table, Tbody, Tr, Td } from '@patternfly/react-table';

import ResourceIcon from 'Components/PatternFly/ResourceIcon';
import { policySeverityIconMap } from 'Components/PatternFly/SeverityIcons';
import { Alert, isDeploymentAlert, isResourceAlert } from 'types/alert.proto';
import { getDateTime } from 'utils/dateUtils';
import { violationsBasePath } from 'routePaths';
import NoDataEmptyState from './NoDataEmptyState';

export type MostRecentViolationsProps = {
    alerts: Alert[];
};

function MostRecentViolations({ alerts }: MostRecentViolationsProps) {
    return (
        <>
            <Title headingLevel="h3" className="pf-v5-u-mb-sm">
                Most recent violations with critical severity
            </Title>
            {alerts.length > 0 ? (
                <Table variant="compact" borders={false}>
                    <Tbody>
                        {alerts.map((alert) => {
                            const { id, time, policy } = alert;

                            // The "Unknown" case should never occur, but we use it here as a safety fallback
                            let icon = <ResourceIcon className="pf-v5-u-mr-sm" kind="Unknown" />;
                            let name = <Truncate content="Unknown Violation" />;

                            if (isDeploymentAlert(alert)) {
                                icon = <ResourceIcon className="pf-v5-u-mr-sm" kind="Deployment" />;
                                name = <Truncate content={alert.deployment.name} />;
                            } else if (isResourceAlert(alert)) {
                                const resourceTypeToKind = {
                                    UNKNOWN: 'Unknown',
                                    SECRETS: 'Secret',
                                    CONFIGMAPS: 'ConfigMap',
                                    CLUSTER_ROLES: 'ClusterRoles',
                                    CLUSTER_ROLE_BINDINGS: 'ClusterRoleBindings',
                                    NETWORK_POLICIES: 'NetworkPolicies',
                                    SECURITY_CONTEXT_CONSTRAINTS: 'SecurityContextConstraints',
                                    EGRESS_FIREWALLS: 'EgressFirewalls',
                                } as const;
                                const kind = resourceTypeToKind[alert.resource.resourceType];
                                icon = <ResourceIcon className="pf-v5-u-mr-sm" kind={kind} />;
                                name = <Truncate content={alert.resource.name} />;
                            }

                            const PolicySeverityIcon = policySeverityIconMap[policy.severity];
                            return (
                                <Tr key={id}>
                                    <Td className="pf-v5-u-p-0" dataLabel="Severity icon">
                                        <PolicySeverityIcon className="pf-v5-u-display-inline" />
                                    </Td>
                                    <Td dataLabel="Violation name">
                                        <Link to={`${violationsBasePath}/${id}`}>
                                            <Truncate content={policy.name} />
                                        </Link>
                                    </Td>
                                    <Td dataLabel="Deployment in violation">
                                        <Flex
                                            direction={{ default: 'row' }}
                                            flexWrap={{ default: 'nowrap' }}
                                        >
                                            {icon}
                                            {name}
                                        </Flex>
                                    </Td>
                                    <Td
                                        modifier="nowrap"
                                        className="pf-v5-u-pr-0 pf-v5-u-text-align-right-on-md"
                                        dataLabel="Time of last violation occurrence"
                                    >
                                        {getDateTime(time)}
                                    </Td>
                                </Tr>
                            );
                        })}
                    </Tbody>
                </Table>
            ) : (
                <NoDataEmptyState />
            )}
        </>
    );
}

export default MostRecentViolations;
