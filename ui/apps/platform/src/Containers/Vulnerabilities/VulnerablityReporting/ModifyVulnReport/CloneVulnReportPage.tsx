import React, { useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
    PageSection,
    Title,
    Divider,
    Flex,
    FlexItem,
    Breadcrumb,
    BreadcrumbItem,
    Bullseye,
    Spinner,
} from '@patternfly/react-core';
import { Wizard } from '@patternfly/react-core/deprecated';
import isEmpty from 'lodash/isEmpty';

import { vulnerabilityConfigurationReportsPath } from 'routePaths';
import useReportFormValues from 'Containers/Vulnerabilities/VulnerablityReporting/forms/useReportFormValues';
import useCreateReport from 'Containers/Vulnerabilities/VulnerablityReporting/api/useCreateReport';
import useFetchReport from 'Containers/Vulnerabilities/VulnerablityReporting/api/useFetchReport';

import PageTitle from 'Components/PageTitle';
import BreadcrumbItemLink from 'Components/BreadcrumbItemLink';
import ReportParametersForm from 'Containers/Vulnerabilities/VulnerablityReporting/forms/ReportParametersForm';
import DeliveryDestinationsForm from 'Containers/Vulnerabilities/VulnerablityReporting/forms/DeliveryDestinationsForm';
import ReportReviewForm from 'Containers/Vulnerabilities/VulnerablityReporting/forms/ReportReviewForm';
import NotFoundMessage from 'Components/NotFoundMessage/NotFoundMessage';
import { getReportFormValuesFromConfiguration } from '../utils';
import ReportFormErrorAlert from './ReportFormErrorAlert';
import ReportFormWizardFooter from './ReportFormWizardFooter';

const wizardStepNames = [
    'Configure report parameters',
    'Configure delivery destinations',
    'Review and create',
];

function CloneVulnReportPage() {
    const navigate = useNavigate();
    const { reportId } = useParams() as { reportId: string };

    const { reportConfiguration, isLoading, error } = useFetchReport(reportId);
    const formik = useReportFormValues();
    const {
        isLoading: isCreating,
        error: createError,
        createReport,
    } = useCreateReport({
        onCompleted: () => {
            formik.resetForm();
            navigate(vulnerabilityConfigurationReportsPath);
        },
    });

    // We fetch the report configuration for the edittable report and then populate the form values
    useEffect(() => {
        if (reportConfiguration) {
            const reportFormValues = getReportFormValuesFromConfiguration(reportConfiguration);
            // We need to clear the reportId and modify the name
            reportFormValues.reportId = '';
            reportFormValues.reportParameters.reportName = `${reportFormValues.reportParameters.reportName} (copy)`;
            formik.setValues(reportFormValues);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [reportConfiguration, formik.setValues]);

    function onCreate() {
        createReport(formik.values);
    }

    // @TODO: This is reused in the Edit and Clone components so we can try to refactor this soon
    function isStepDisabled(stepName: string | undefined): boolean {
        if (stepName === wizardStepNames[0]) {
            return false;
        }
        if (stepName === wizardStepNames[1]) {
            return !isEmpty(formik.errors.reportParameters);
        }
        if (stepName === wizardStepNames[2]) {
            return (
                !isEmpty(formik.errors.reportParameters) ||
                !isEmpty(formik.errors.deliveryDestinations) ||
                !isEmpty(formik.errors.schedule)
            );
        }
        return false;
    }

    function onClose() {
        navigate(vulnerabilityConfigurationReportsPath);
    }

    const wizardSteps = [
        {
            name: wizardStepNames[0],
            component: <ReportParametersForm title={wizardStepNames[0]} formik={formik} />,
        },
        {
            name: wizardStepNames[1],
            component: <DeliveryDestinationsForm title={wizardStepNames[1]} formik={formik} />,
            isDisabled: isStepDisabled(wizardStepNames[1]),
        },
        {
            name: wizardStepNames[2],
            component: <ReportReviewForm title={wizardStepNames[2]} formValues={formik.values} />,
            nextButtonText: 'Create',
            isDisabled: isStepDisabled(wizardStepNames[2]),
        },
    ];

    if (error) {
        return (
            <NotFoundMessage
                title="Error fetching the report configuration"
                message={error}
                actionText="Go to reports"
                url={vulnerabilityConfigurationReportsPath}
            />
        );
    }

    if (isLoading) {
        return (
            <Bullseye>
                <Spinner />
            </Bullseye>
        );
    }

    return (
        <>
            <PageTitle title="Create vulnerability report" />
            <ReportFormErrorAlert error={createError} />
            <PageSection variant="light" className="pf-v5-u-py-md">
                <Breadcrumb>
                    <BreadcrumbItemLink to={vulnerabilityConfigurationReportsPath}>
                        Vulnerability reporting
                    </BreadcrumbItemLink>
                    <BreadcrumbItem isActive>Clone report</BreadcrumbItem>
                </Breadcrumb>
            </PageSection>
            <Divider component="div" />
            <PageSection variant="light" padding={{ default: 'noPadding' }}>
                <Flex direction={{ default: 'column' }} className="pf-v5-u-py-lg pf-v5-u-px-lg">
                    <FlexItem>
                        <Title headingLevel="h1">Clone report</Title>
                    </FlexItem>
                    <FlexItem>
                        Configure reports, define collections, and assign delivery destinations to
                        report on vulnerabilities across the organization.
                    </FlexItem>
                </Flex>
            </PageSection>
            <Divider component="div" />
            <PageSection padding={{ default: 'noPadding' }} isCenterAligned>
                <Wizard
                    navAriaLabel="Report clone steps"
                    mainAriaLabel="Report clone content"
                    hasNoBodyPadding
                    steps={wizardSteps}
                    onSave={onCreate}
                    onClose={onClose}
                    footer={
                        <ReportFormWizardFooter
                            wizardSteps={wizardSteps}
                            saveText="Create"
                            onSave={onCreate}
                            isSaving={isCreating}
                            isStepDisabled={isStepDisabled}
                        />
                    }
                />
            </PageSection>
        </>
    );
}

export default CloneVulnReportPage;
