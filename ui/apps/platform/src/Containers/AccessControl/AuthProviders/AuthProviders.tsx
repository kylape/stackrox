import React, { ReactElement, useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { selectors } from 'reducers';
import { useLocation, useNavigate, useParams, Link } from 'react-router-dom-v5-compat';
import ExternalLink from 'Components/PatternFly/IconText/ExternalLink';
import {
    Alert,
    Bullseye,
    Button,
    DropdownItem,
    DropdownList,
    ExpandableSection,
    Flex,
    PageSection,
    pluralize,
    Spinner,
    Title,
} from '@patternfly/react-core';

import MenuDropdown from 'Components/PatternFly/MenuDropdown';
import EmptyStateTemplate from 'Components/EmptyStateTemplate';
import NotFoundMessage from 'Components/NotFoundMessage';
import useAnalytics, { INVITE_USERS_MODAL_OPENED } from 'hooks/useAnalytics';
import { actions as authActions, types as authActionTypes } from 'reducers/auth';
import { actions as groupActions } from 'reducers/groups';
import { actions as inviteActions } from 'reducers/invite';
import { actions as roleActions, types as roleActionTypes } from 'reducers/roles';
import { AuthProvider, AuthProviderInfo, Group } from 'services/AuthService';
import usePermissions from 'hooks/usePermissions';
import { integrationsPath } from 'routePaths';
import { getVersionedDocs } from 'utils/versioning';
import useMetadata from 'hooks/useMetadata';
import { getEntityPath, getQueryObject } from '../accessControlPaths';
import { mergeGroupsWithAuthProviders } from './authProviders.utils';

import AccessControlPageTitle from '../AccessControlPageTitle';

import AccessControlDescription from '../AccessControlDescription';
import AuthProviderForm from './AuthProviderForm';
import AuthProvidersList from './AuthProvidersList';
import AccessControlBreadcrumbs from '../AccessControlBreadcrumbs';
import AccessControlHeading from '../AccessControlHeading';
import AccessControlHeaderActionBar from '../AccessControlHeaderActionBar';

const entityType = 'AUTH_PROVIDER';

const authProviderNew = {
    id: '',
    name: '',
    type: 'oidc',
    config: {},
} as AuthProvider; // TODO what are the minimum properties for create request?

type AuthProviderState = {
    authProviders: AuthProvider[];
    groups: Group[];
    isFetchingAuthProviders: boolean;
    isFetchingRoles: boolean;
    availableProviderTypes: AuthProviderInfo[];
};

const authProviderState = createStructuredSelector<AuthProviderState>({
    authProviders: selectors.getAvailableAuthProviders,
    groups: selectors.getRuleGroups,
    isFetchingAuthProviders: (state) =>
        selectors.getLoadingStatus(state, authActionTypes.FETCH_AUTH_PROVIDERS) as boolean,
    isFetchingRoles: (state) =>
        selectors.getLoadingStatus(state, roleActionTypes.FETCH_ROLES) as boolean,
    availableProviderTypes: selectors.getAvailableProviderTypes,
});

function getNewAuthProviderObj(type) {
    return { ...authProviderNew, type };
}

function AuthProviders(): ReactElement {
    const { hasReadWriteAccess } = usePermissions();
    const hasWriteAccessForPage = hasReadWriteAccess('Access');
    const navigate = useNavigate();
    const { search } = useLocation();
    const queryObject = getQueryObject(search);
    const { action, type } = queryObject;
    const { entityId } = useParams();
    const dispatch = useDispatch();
    const { analyticsTrack } = useAnalytics();
    const { version } = useMetadata();

    const [isInfoExpanded, setIsInfoExpanded] = useState(false);
    const {
        authProviders,
        groups,
        isFetchingAuthProviders,
        isFetchingRoles,
        availableProviderTypes,
    } = useSelector(authProviderState);

    const authProvidersWithRules = mergeGroupsWithAuthProviders(authProviders, groups);

    useEffect(() => {
        dispatch(authActions.fetchAuthProviders.request());
        dispatch(roleActions.fetchRoles.request());
        dispatch(groupActions.fetchGroups.request());
    }, [dispatch]);

    function onClickInviteUsers() {
        // track request to invite
        analyticsTrack(INVITE_USERS_MODAL_OPENED);

        dispatch(inviteActions.setInviteModalVisibility(true));
    }

    function onClickCreate(event, value) {
        navigate(
            getEntityPath(entityType, undefined, {
                ...queryObject,
                action: 'create',
                type: value,
            })
        );
    }

    function onClickEdit() {
        navigate(getEntityPath(entityType, entityId, { ...queryObject, action: 'edit' }));
    }

    function onClickCancel() {
        dispatch(authActions.setSaveAuthProviderStatus(null));

        // The entityId is undefined for create and defined for update.
        navigate(getEntityPath(entityType, entityId, { ...queryObject, action: undefined }));
    }

    function getProviderLabel(): string {
        const provider: Partial<AuthProviderInfo> =
            availableProviderTypes.find(({ value }) => value === type) ?? {};
        return provider.label ?? 'auth';
    }

    const onToggle = (_isExpanded: boolean) => {
        setIsInfoExpanded(_isExpanded);
    };

    const selectedAuthProvider = authProviders.find(({ id }) => id === entityId);
    const hasAction = Boolean(action);
    const isList = typeof entityId !== 'string' && !hasAction;

    // if user elected to ignore a save error, don't pester them if they return to the form
    if (isList) {
        dispatch(authActions.setSaveAuthProviderStatus(null));
    }

    const dropdownItems = availableProviderTypes.map(({ value, label }) => (
        <DropdownItem key={value} value={value}>
            {label}
        </DropdownItem>
    ));

    return (
        <>
            <AccessControlPageTitle entityType={entityType} isList={isList} />
            {isList ? (
                <>
                    <AccessControlHeading entityType={entityType} />
                    <AccessControlHeaderActionBar
                        displayComponent={
                            <AccessControlDescription>
                                Configure authentication providers and rules to assign roles to
                                users
                            </AccessControlDescription>
                        }
                        inviteComponent={
                            hasWriteAccessForPage && (
                                <Button variant="secondary" onClick={onClickInviteUsers}>
                                    Invite users
                                </Button>
                            )
                        }
                        actionComponent={
                            hasWriteAccessForPage && (
                                <MenuDropdown
                                    toggleClassName="auth-provider-dropdown pf-v5-u-ml-md"
                                    toggleText="Create auth provider"
                                    toggleVariant="primary"
                                    onSelect={onClickCreate}
                                    popperProps={{
                                        position: 'end',
                                    }}
                                >
                                    <DropdownList>{dropdownItems}</DropdownList>
                                </MenuDropdown>
                            )
                        }
                    />
                    <PageSection variant="light">
                        <Alert
                            isInline
                            variant="info"
                            title="Consider using short-lived tokens for machine-to-machine communications
                            such as CI/CD pipelines, scripts, and other automation."
                            component="p"
                        >
                            <Flex
                                direction={{ default: 'column' }}
                                spaceItems={{ default: 'spaceItemsMd' }}
                            >
                                <Flex direction={{ default: 'row' }}>
                                    <ExternalLink>
                                        <a
                                            href={getVersionedDocs(
                                                version,
                                                'operating/managing-user-access#configure-short-lived-access'
                                            )}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                        >
                                            How to configure short-lived access
                                        </a>
                                    </ExternalLink>
                                    {hasWriteAccessForPage && (
                                        <Link
                                            to={`${integrationsPath}/authProviders/machineAccess/create`}
                                        >
                                            Create a machine access configuration
                                        </Link>
                                    )}
                                </Flex>
                                <ExpandableSection
                                    toggleText="More resources"
                                    onToggle={(_event, _isExpanded: boolean) =>
                                        onToggle(_isExpanded)
                                    }
                                    isExpanded={isInfoExpanded}
                                >
                                    <Flex direction={{ default: 'column' }}>
                                        <ExternalLink>
                                            <a
                                                href="https://github.com/stackrox/central-login"
                                                target="_blank"
                                                rel="noopener noreferrer"
                                            >
                                                GitHub Action for short-lived access
                                            </a>
                                        </ExternalLink>
                                        <ExternalLink>
                                            <a
                                                href="https://hub.tekton.dev/tekton/task/rhacs-m2m-authenticate"
                                                target="_blank"
                                                rel="noopener noreferrer"
                                            >
                                                Tekton Task for short-lived access
                                            </a>
                                        </ExternalLink>
                                    </Flex>
                                </ExpandableSection>
                            </Flex>
                        </Alert>
                    </PageSection>
                </>
            ) : (
                <AccessControlBreadcrumbs
                    entityType={entityType}
                    entityName={
                        action === 'create'
                            ? `Create ${getProviderLabel()} provider`
                            : selectedAuthProvider?.name
                    }
                />
            )}
            <PageSection variant={isList ? 'default' : 'light'}>
                {isFetchingAuthProviders || isFetchingRoles ? (
                    <Bullseye>
                        <Spinner />
                    </Bullseye>
                ) : isList ? (
                    <PageSection variant="light">
                        <Title headingLevel="h2">
                            {pluralize(authProvidersWithRules.length, 'result')} found
                        </Title>
                        {authProvidersWithRules.length === 0 && (
                            <EmptyStateTemplate title="No auth providers" headingLevel="h3">
                                Please add one.
                            </EmptyStateTemplate>
                        )}
                        {authProvidersWithRules.length > 0 && (
                            <AuthProvidersList
                                entityId={entityId}
                                authProviders={authProvidersWithRules}
                            />
                        )}
                    </PageSection>
                ) : typeof entityId === 'string' && !selectedAuthProvider ? (
                    <NotFoundMessage
                        title="Auth provider does not exist"
                        message={`Auth provider id: ${entityId}`}
                        actionText="Auth providers"
                        url={getEntityPath(entityType)}
                    />
                ) : (
                    <AuthProviderForm
                        isActionable={hasWriteAccessForPage}
                        action={action}
                        selectedAuthProvider={selectedAuthProvider ?? getNewAuthProviderObj(type)}
                        onClickCancel={onClickCancel}
                        onClickEdit={onClickEdit}
                    />
                )}
            </PageSection>
        </>
    );
}

export default AuthProviders;
