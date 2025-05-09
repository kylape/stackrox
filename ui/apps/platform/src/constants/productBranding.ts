import rhacsFavicon from 'images/rh-favicon.ico';
import stackroxFavicon from 'images/sr-favicon.ico';
import rhacsLogoSvg from 'images/RHACS-Logo.svg';
import stackroxLogoSvg from 'images/StackRox-Logo.svg';

export type ProductBranding = 'RHACS_BRANDING' | 'STACKROX_BRANDING';

export interface BrandingAssets {
    /** The branding value used to generate assets */
    type: ProductBranding;
    /** The source path to the main branding logo in SVG format */
    logoSvg: string;
    /** Alt text for the main branding logo */
    logoAltText: string;
    /** Value to use as the base in the <title> element */
    basePageTitle: string;
    /** Value for default subject of report e-mail */
    reportName: string;
    /** Shortened version of product name */
    shortName: string;
    /** Absolute path to the page favicon */
    favicon: string;
}

const rhacsBranding: BrandingAssets = {
    type: 'RHACS_BRANDING',
    logoSvg: rhacsLogoSvg,
    logoAltText: 'Red Hat Advanced Cluster Security Logo',
    basePageTitle: 'Red Hat Advanced Cluster Security',
    reportName: 'Red Hat Advanced Cluster Security (RHACS)',
    shortName: 'RHACS',
    favicon: rhacsFavicon,
};

const stackroxBranding: BrandingAssets = {
    type: 'STACKROX_BRANDING',
    logoSvg: stackroxLogoSvg,
    logoAltText: 'StackRox Logo',
    basePageTitle: 'StackRox',
    reportName: 'StackRox',
    shortName: 'StackRox',
    favicon: stackroxFavicon,
};

// @TODO: This should be renamed to getProductBrandingAssets to be more specific. It would be nice
// to have a function to just get the product brand itself (ie. RHACS_BRANDING, STACKROX_BRANDING)
export function getProductBranding(): BrandingAssets {
    const productBranding: string | undefined = process.env.ROX_PRODUCT_BRANDING;

    switch (productBranding) {
        case 'RHACS_BRANDING':
            return rhacsBranding;
        default:
            return stackroxBranding;
    }
}
