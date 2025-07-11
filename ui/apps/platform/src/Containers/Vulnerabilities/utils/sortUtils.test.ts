import {
    getScoreVersionsForTopCVSS,
    getSeveritySortOptions,
    sortCveDistroList,
    syncSeveritySortOption,
} from './sortUtils';

describe('sortCveDistroList', () => {
    it('should return an array of objects sorted by operating system priority', () => {
        const summaries = [{ operatingSystem: 'amzn:2' }];

        expect(sortCveDistroList(summaries)).toEqual([
            { distro: 'amzn', operatingSystem: 'amzn:2' },
        ]);

        summaries.push({ operatingSystem: 'alpine:v.3.2' });
        expect(sortCveDistroList(summaries)).toEqual([
            { distro: 'alpine', operatingSystem: 'alpine:v.3.2' },
            { distro: 'amzn', operatingSystem: 'amzn:2' },
        ]);

        summaries.push({ operatingSystem: 'amzn:2018.03' });
        expect(sortCveDistroList(summaries)).toEqual([
            { distro: 'alpine', operatingSystem: 'alpine:v.3.2' },
            { distro: 'amzn', operatingSystem: 'amzn:2' },
            { distro: 'amzn', operatingSystem: 'amzn:2018.03' },
        ]);

        // Add an "unknown" OS
        summaries.push({ operatingSystem: 'windows:xp' });
        expect(sortCveDistroList(summaries)).toEqual([
            { distro: 'alpine', operatingSystem: 'alpine:v.3.2' },
            { distro: 'amzn', operatingSystem: 'amzn:2' },
            { distro: 'amzn', operatingSystem: 'amzn:2018.03' },
            { distro: 'other', operatingSystem: 'windows:xp' },
        ]);

        summaries.push({ operatingSystem: 'debian:9' });
        expect(sortCveDistroList(summaries)).toEqual([
            { distro: 'debian', operatingSystem: 'debian:9' },
            { distro: 'alpine', operatingSystem: 'alpine:v.3.2' },
            { distro: 'amzn', operatingSystem: 'amzn:2' },
            { distro: 'amzn', operatingSystem: 'amzn:2018.03' },
            { distro: 'other', operatingSystem: 'windows:xp' },
        ]);

        summaries.push({ operatingSystem: 'ubuntu:20.04' });
        expect(sortCveDistroList(summaries)).toEqual([
            { distro: 'ubuntu', operatingSystem: 'ubuntu:20.04' },
            { distro: 'debian', operatingSystem: 'debian:9' },
            { distro: 'alpine', operatingSystem: 'alpine:v.3.2' },
            { distro: 'amzn', operatingSystem: 'amzn:2' },
            { distro: 'amzn', operatingSystem: 'amzn:2018.03' },
            { distro: 'other', operatingSystem: 'windows:xp' },
        ]);

        summaries.push({ operatingSystem: 'rhel:9' });
        expect(sortCveDistroList(summaries)).toEqual([
            { distro: 'rhel', operatingSystem: 'rhel:9' },
            { distro: 'ubuntu', operatingSystem: 'ubuntu:20.04' },
            { distro: 'debian', operatingSystem: 'debian:9' },
            { distro: 'alpine', operatingSystem: 'alpine:v.3.2' },
            { distro: 'amzn', operatingSystem: 'amzn:2' },
            { distro: 'amzn', operatingSystem: 'amzn:2018.03' },
            { distro: 'other', operatingSystem: 'windows:xp' },
        ]);

        summaries.push({ operatingSystem: 'centos:8' });
        expect(sortCveDistroList(summaries)).toEqual([
            { distro: 'rhel', operatingSystem: 'rhel:9' },
            { distro: 'centos', operatingSystem: 'centos:8' },
            { distro: 'ubuntu', operatingSystem: 'ubuntu:20.04' },
            { distro: 'debian', operatingSystem: 'debian:9' },
            { distro: 'alpine', operatingSystem: 'alpine:v.3.2' },
            { distro: 'amzn', operatingSystem: 'amzn:2' },
            { distro: 'amzn', operatingSystem: 'amzn:2018.03' },
            { distro: 'other', operatingSystem: 'windows:xp' },
        ]);
    });
});

describe('getScoreVersionsForTopCVSS', () => {
    it('should return the correct score versions for the topCVSS', () => {
        // Empty list
        expect(getScoreVersionsForTopCVSS(9.5, [])).toEqual([]);

        // Basic checks
        expect(
            getScoreVersionsForTopCVSS(9.4, [
                { cvss: 9.4300001, scoreVersion: 'V1' },
                { cvss: 8.0, scoreVersion: 'V2' },
                { cvss: 9.4, scoreVersion: 'V3' },
                { cvss: 9.4212, scoreVersion: 'V4' },
                { cvss: 9.48, scoreVersion: 'V5' },
                { cvss: -9.4300001, scoreVersion: 'V6' },
                { cvss: 0.0, scoreVersion: 'V7' },
                { cvss: NaN, scoreVersion: 'V8' },
                { cvss: Infinity, scoreVersion: 'V9' },
                { cvss: -Infinity, scoreVersion: 'V10' },
            ])
        ).toEqual(['V1', 'V3', 'V4']);

        // Check that duplicates are removed
        expect(
            getScoreVersionsForTopCVSS(9.4, [
                { cvss: 9.4, scoreVersion: 'V1' },
                { cvss: 9.4, scoreVersion: 'V1' },
            ])
        ).toEqual(['V1']);

        // Check that items are sorted correctly
        expect(
            getScoreVersionsForTopCVSS(9.4, [
                { cvss: 9.4, scoreVersion: 'V3' },
                { cvss: 9.4, scoreVersion: 'V1' },
                { cvss: 9.4, scoreVersion: 'V2' },
            ])
        ).toEqual(['V1', 'V2', 'V3']);
    });
});

describe('getSeveritySortOptions', () => {
    it('should return all severity sort options when no severity filters are applied', () => {
        expect(getSeveritySortOptions(undefined)).toEqual([
            { field: 'Critical Severity Count' },
            { field: 'Important Severity Count' },
            { field: 'Moderate Severity Count' },
            { field: 'Low Severity Count' },
            { field: 'Unknown Severity Count' },
        ]);
    });

    it('should return only the visible severity sort options when some severities filters are applied', () => {
        expect(getSeveritySortOptions(['Critical'])).toEqual([
            { field: 'Critical Severity Count' },
        ]);

        expect(getSeveritySortOptions(['Critical', 'Low'])).toEqual([
            { field: 'Critical Severity Count' },
            { field: 'Low Severity Count' },
        ]);
    });

    it('should return all severity sort options when all severity filters are applied', () => {
        expect(
            getSeveritySortOptions(['Critical', 'Important', 'Moderate', 'Low', 'Unknown'])
        ).toEqual([
            { field: 'Critical Severity Count' },
            { field: 'Important Severity Count' },
            { field: 'Moderate Severity Count' },
            { field: 'Low Severity Count' },
            { field: 'Unknown Severity Count' },
        ]);
    });
});

describe('syncSeveritySortOption', () => {
    it('should not update the sort option if the current sort option is not sorting by severity', () => {
        const searchFilter = {};
        const currentSortOption = { field: 'Image', reversed: false };
        const applySort = vi.fn();

        syncSeveritySortOption(searchFilter, currentSortOption, applySort);

        expect(applySort).not.toHaveBeenCalled();
    });

    it('should update the sort option if the current sort option is sorting by severity and a new severity filter is applied', () => {
        const searchFilter = { SEVERITY: ['Critical', 'Important'] };
        const currentSortOption = [{ field: 'Critical Severity Count', reversed: false }];
        const applySort = vi.fn();

        syncSeveritySortOption(searchFilter, currentSortOption, applySort);

        expect(applySort).toHaveBeenCalledWith([
            { field: 'Critical Severity Count', direction: 'asc' },
            { field: 'Important Severity Count', direction: 'asc' },
        ]);
    });
});
