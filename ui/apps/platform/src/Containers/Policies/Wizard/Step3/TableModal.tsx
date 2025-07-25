import React, { useCallback, useState } from 'react';
import { Link } from 'react-router-dom-v5-compat';
import {
    Button,
    Modal,
    ModalBoxBody,
    ModalBoxFooter,
    PageSection,
    TextInput,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import isEqual from 'lodash/isEqual';
import pluralize from 'pluralize';

import TableCellValue from 'Components/TableCellValue/TableCellValue';
import { IntegrationTableColumnDescriptor } from 'Containers/Integrations/utils/tableColumnDescriptor';
import useTableSelection from 'hooks/useTableSelection';
import { ClientPolicyValue } from 'types/policy.proto';
import { SignatureIntegration } from 'types/signatureIntegration.proto';

type TableModalProps = {
    setValue: (value: ClientPolicyValue) => void;
    value: ClientPolicyValue;
    readOnly?: boolean;
    rows: { id: string; link: string }[];
    columns: IntegrationTableColumnDescriptor<SignatureIntegration>[];
    typeText: string;
};

function TableModal({
    setValue,
    value,
    readOnly = false,
    rows,
    columns,
    typeText,
}: TableModalProps): React.ReactElement {
    const [isModalOpen, setIsModalOpen] = useState(false);

    const isPreSelected = useCallback(
        (row: { id: string }) =>
            Array.isArray(value.arrayValue) ? value.arrayValue.includes(row.id) : false,
        [value]
    );

    const { selected, onSelect, onSelectAll, allRowsSelected, onResetAll, getSelectedIds } =
        useTableSelection(rows, isPreSelected);

    function onCloseModalHandler() {
        onResetAll();
        setIsModalOpen(false);
    }

    function onSaveHandler() {
        setValue({ arrayValue: getSelectedIds() });
        setIsModalOpen(false);
    }

    return (
        <>
            <TextInput
                data-testid="table-modal-text-input"
                isDisabled
                value={
                    Array.isArray(value.arrayValue) && value.arrayValue.length !== 0
                        ? `Selected ${value.arrayValue.length} ${pluralize(
                              typeText,
                              value.arrayValue?.length
                          )}`
                        : `Add ${typeText}s`
                }
            />
            <Button
                key="open-select-modal"
                data-testid="table-modal-open-button"
                variant="primary"
                onClick={() => {
                    setIsModalOpen(true);
                }}
            >
                {readOnly ? 'View' : 'Select'}
            </Button>
            <Modal
                title={`Add ${typeText}s to policy criteria`}
                isOpen={isModalOpen}
                variant="large"
                onClose={onCloseModalHandler}
                aria-label={`Select ${typeText}s modal`}
                hasNoBodyWrapper
            >
                <ModalBoxBody>
                    <PageSection variant="light">
                        {!!rows.length && (
                            <>
                                Select {typeText}s from the table below.
                                <Table
                                    variant="compact"
                                    isStickyHeader
                                    data-testid="table-modal-table"
                                >
                                    <Thead>
                                        <Tr>
                                            <Th
                                                select={{
                                                    onSelect: onSelectAll,
                                                    isSelected: allRowsSelected,
                                                    isHeaderSelectDisabled: readOnly,
                                                }}
                                            />
                                            {columns.map((column) => {
                                                return (
                                                    <Th key={column.Header} modifier="wrap">
                                                        {column.Header}
                                                    </Th>
                                                );
                                            })}
                                        </Tr>
                                    </Thead>
                                    <Tbody>
                                        {rows.map((row, rowIndex) => {
                                            const { id, link } = row;
                                            return (
                                                <Tr key={id}>
                                                    <Td
                                                        key={id}
                                                        select={{
                                                            rowIndex,
                                                            onSelect,
                                                            isSelected: selected[rowIndex],
                                                            isDisabled: readOnly,
                                                        }}
                                                    />
                                                    {columns.map((column) => {
                                                        if (column.Header === 'Name') {
                                                            return (
                                                                <Td
                                                                    key="name"
                                                                    dataLabel={column.Header}
                                                                >
                                                                    <Link to={link}>
                                                                        <TableCellValue
                                                                            row={row}
                                                                            column={column}
                                                                        />
                                                                    </Link>
                                                                </Td>
                                                            );
                                                        }
                                                        return (
                                                            <Td
                                                                key={column.Header}
                                                                dataLabel={column.Header}
                                                            >
                                                                <TableCellValue
                                                                    row={row}
                                                                    column={column}
                                                                />
                                                            </Td>
                                                        );
                                                    })}
                                                </Tr>
                                            );
                                        })}
                                    </Tbody>
                                </Table>
                            </>
                        )}
                        {!rows.length && (
                            <div data-testid="table-modal-empty-state">
                                Please configure {typeText}s to add them as policy criteria.
                            </div>
                        )}
                    </PageSection>
                </ModalBoxBody>
                <ModalBoxFooter>
                    <Button
                        key="save"
                        variant="primary"
                        data-testid="table-modal-save-btn"
                        onClick={onSaveHandler}
                        isDisabled={
                            readOnly || isEqual(value.arrayValue, getSelectedIds()) || !rows.length
                        }
                    >
                        Save
                    </Button>
                    <Button
                        key="cancel"
                        variant="secondary"
                        data-testid="table-modal-cancel-btn"
                        onClick={onCloseModalHandler}
                    >
                        Cancel
                    </Button>
                </ModalBoxFooter>
            </Modal>
        </>
    );
}

export default TableModal;
