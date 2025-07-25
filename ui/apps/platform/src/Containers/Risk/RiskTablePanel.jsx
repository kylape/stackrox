import React, { useContext, useState, useCallback } from 'react';
import PropTypes from 'prop-types';
import { useNavigate } from 'react-router-dom-v5-compat';
import useDeepCompareEffect from 'use-deep-compare-effect';
import { Bullseye } from '@patternfly/react-core';
import { ExclamationTriangleIcon } from '@patternfly/react-icons';

import EmptyStateTemplate from 'Components/EmptyStateTemplate/EmptyStateTemplate';
import TableHeader from 'Components/TableHeader';
import { PanelNew, PanelBody, PanelHead, PanelHeadEnd } from 'Components/Panel';
import TablePagination from 'Components/TablePagination';
import { DEFAULT_PAGE_SIZE } from 'Components/Table';
import { searchParams, sortParams, pagingParams } from 'constants/searchParams';
import workflowStateContext from 'Containers/workflowStateContext';
import {
    fetchDeploymentsWithProcessInfoLegacy as fetchDeploymentsWithProcessInfo,
    fetchDeploymentsCountLegacy,
} from 'services/DeploymentsService';
import { getAxiosErrorMessage } from 'utils/responseErrorUtils';
import {
    convertToRestSearch,
    convertSortToGraphQLFormat,
    convertSortToRestFormat,
} from 'utils/searchUtils';
import RiskTable from './RiskTable';

const DEFAULT_RISK_SORT = [{ id: 'Deployment Risk Priority', desc: false }];
function RiskTablePanel({
    selectedDeploymentId,
    setSelectedDeploymentId,
    isViewFiltered,
    setIsViewFiltered,
}) {
    const navigate = useNavigate();
    const workflowState = useContext(workflowStateContext);
    const pageSearch = workflowState.search[searchParams.page];
    const sortOption = workflowState.sort[sortParams.page] || DEFAULT_RISK_SORT;
    const currentPage = workflowState.paging[pagingParams.page];

    const [currentDeployments, setCurrentDeployments] = useState([]);
    const [errorMessageDeployments, setErrorMessageDeployments] = useState('');
    const [deploymentCount, setDeploymentsCount] = useState(0);

    function setPage(newPage) {
        navigate(workflowState.setPage(newPage).toUrl());
    }
    const setSortOption = useCallback(
        (newSortOption) => {
            const convertedSortOption = convertSortToGraphQLFormat(newSortOption);

            const newUrl = workflowState.setSort(convertedSortOption).setPage(0).toUrl();

            navigate(newUrl);
        },
        [navigate, workflowState]
    );

    /*
     * Compute outside hook to avoid double requests if no page search options
     * before and after response to request for searchOptions.
     */
    const restSearch = convertToRestSearch(pageSearch || {});
    const restSort = convertSortToRestFormat(sortOption);

    useDeepCompareEffect(() => {
        fetchDeploymentsWithProcessInfo(restSearch, restSort, currentPage, DEFAULT_PAGE_SIZE)
            .then(setCurrentDeployments)
            .catch((error) => {
                setCurrentDeployments([]);
                setErrorMessageDeployments(getAxiosErrorMessage(error));
            });

        /*
         * Although count does not depend on change to sort option or page offset,
         * request in case of change to count of deployments in Kubernetes environment.
         */
        fetchDeploymentsCountLegacy(restSearch)
            .then(setDeploymentsCount)
            .catch(() => {
                setDeploymentsCount(0);
            });

        if (restSearch.length) {
            setIsViewFiltered(true);
        } else {
            setIsViewFiltered(false);
        }
    }, [restSearch, restSort, currentPage]);

    return (
        <PanelNew testid="panel">
            <PanelHead>
                <TableHeader
                    length={deploymentCount}
                    type="deployment"
                    isViewFiltered={isViewFiltered}
                />
                <PanelHeadEnd>
                    <TablePagination
                        page={currentPage}
                        dataLength={deploymentCount}
                        pageSize={DEFAULT_PAGE_SIZE}
                        setPage={setPage}
                    />
                </PanelHeadEnd>
            </PanelHead>
            <PanelBody>
                {errorMessageDeployments ? (
                    <Bullseye>
                        <EmptyStateTemplate
                            title="Unable to load deployments"
                            headingLevel="h2"
                            icon={ExclamationTriangleIcon}
                            iconClassName="pf-v5-u-warning-color-100"
                        >
                            {errorMessageDeployments}
                        </EmptyStateTemplate>
                    </Bullseye>
                ) : (
                    <RiskTable
                        currentDeployments={currentDeployments}
                        setSelectedDeploymentId={setSelectedDeploymentId}
                        selectedDeploymentId={selectedDeploymentId}
                        setSortOption={setSortOption}
                    />
                )}
            </PanelBody>
        </PanelNew>
    );
}

RiskTablePanel.propTypes = {
    selectedDeploymentId: PropTypes.string,
    setSelectedDeploymentId: PropTypes.func.isRequired,
    isViewFiltered: PropTypes.bool.isRequired,
    setIsViewFiltered: PropTypes.func.isRequired,
};

RiskTablePanel.defaultProps = {
    selectedDeploymentId: null,
};

export default RiskTablePanel;
