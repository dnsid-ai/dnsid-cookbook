/**
 * Health spending indicators served by publicdata.test.
 *
 * Values are rounded approximations of WHO Global Health Expenditure Database
 * and OECD Health Statistics figures for 2021. They are here to give the
 * researchers something realistic to compare, not to be cited.
 */
export interface HealthSpending {
  iso3: string;
  country: string;
  year: number;
  /** Current health expenditure as a share of GDP, percent. */
  che_pct_gdp: number;
  /** Current health expenditure per capita, US dollars at purchasing power parity. */
  che_per_capita_usd_ppp: number;
  /** Government and compulsory schemes as a share of current health expenditure, percent. */
  public_share_pct: number;
  /** Out-of-pocket payments as a share of current health expenditure, percent. */
  out_of_pocket_pct: number;
}

export const SOURCE =
  'Approximated from WHO GHED and OECD Health Statistics (2021). Illustrative; not for citation.';

const rows: HealthSpending[] = [
  { iso3: 'USA', country: 'United States', year: 2021, che_pct_gdp: 17.4, che_per_capita_usd_ppp: 12_000, public_share_pct: 57, out_of_pocket_pct: 10 },
  { iso3: 'DEU', country: 'Germany', year: 2021, che_pct_gdp: 12.9, che_per_capita_usd_ppp: 7_400, public_share_pct: 78, out_of_pocket_pct: 12 },
  { iso3: 'FRA', country: 'France', year: 2021, che_pct_gdp: 12.3, che_per_capita_usd_ppp: 6_600, public_share_pct: 77, out_of_pocket_pct: 9 },
  { iso3: 'GBR', country: 'United Kingdom', year: 2021, che_pct_gdp: 12.4, che_per_capita_usd_ppp: 5_400, public_share_pct: 83, out_of_pocket_pct: 13 },
  { iso3: 'CAN', country: 'Canada', year: 2021, che_pct_gdp: 12.3, che_per_capita_usd_ppp: 6_300, public_share_pct: 74, out_of_pocket_pct: 13 },
  { iso3: 'JPN', country: 'Japan', year: 2021, che_pct_gdp: 10.8, che_per_capita_usd_ppp: 5_250, public_share_pct: 85, out_of_pocket_pct: 12 },
  { iso3: 'SWE', country: 'Sweden', year: 2021, che_pct_gdp: 11.3, che_per_capita_usd_ppp: 6_700, public_share_pct: 86, out_of_pocket_pct: 13 },
  { iso3: 'KOR', country: 'South Korea', year: 2021, che_pct_gdp: 9.3, che_per_capita_usd_ppp: 4_600, public_share_pct: 61, out_of_pocket_pct: 30 },
  { iso3: 'MEX', country: 'Mexico', year: 2021, che_pct_gdp: 6.1, che_per_capita_usd_ppp: 1_200, public_share_pct: 50, out_of_pocket_pct: 41 },
  { iso3: 'BRA', country: 'Brazil', year: 2021, che_pct_gdp: 9.9, che_per_capita_usd_ppp: 1_600, public_share_pct: 45, out_of_pocket_pct: 23 },
  { iso3: 'IND', country: 'India', year: 2021, che_pct_gdp: 3.3, che_per_capita_usd_ppp: 250, public_share_pct: 40, out_of_pocket_pct: 50 },
  { iso3: 'NGA', country: 'Nigeria', year: 2021, che_pct_gdp: 3.4, che_per_capita_usd_ppp: 180, public_share_pct: 15, out_of_pocket_pct: 75 },
];

export const byIso3 = new Map(rows.map((r) => [r.iso3, r]));
export const countries = rows.map(({ iso3, country }) => ({ iso3, country }));
