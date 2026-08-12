/** Approx. employee tax presets — estimates only, not advice. */
export const COUNTRIES = [
  { id: "FR", name: "France", social: 22, tax: 0, socialLabel: "Cotisations salariales (%)", taxLabel: "Impôt PAS (%)", note: "salarié non-cadre (approx.)" },
  { id: "BE", name: "Belgique", social: 13.1, tax: 25, socialLabel: "ONSS salarié (%)", taxLabel: "Précompte pro. (%)", note: "approx. employé" },
  { id: "CH", name: "Suisse", social: 6.4, tax: 12, socialLabel: "AVS/AI/APG + chôm. (%)", taxLabel: "Impôts (approx.) (%)", note: "varie fort par canton" },
  { id: "DE", name: "Allemagne", social: 20, tax: 14, socialLabel: "Sozialabgaben (%)", taxLabel: "Lohnsteuer (approx.) (%)", note: "approx. Arbeitnehmer" },
  { id: "ES", name: "Espagne", social: 6.5, tax: 12, socialLabel: "Seg. Social empleado (%)", taxLabel: "IRPF (%)", note: "approx." },
  { id: "IT", name: "Italie", social: 9.2, tax: 15, socialLabel: "Contributi (%)", taxLabel: "IRPEF (approx.) (%)", note: "approx." },
  { id: "PT", name: "Portugal", social: 11, tax: 10, socialLabel: "Segurança Social (%)", taxLabel: "IRS (%)", note: "approx." },
  { id: "NL", name: "Pays-Bas", social: 0, tax: 28, socialLabel: "Premies werknemer (%)", taxLabel: "Loonheffing (approx.) (%)", note: "souvent via loonheffing" },
  { id: "GB", name: "Royaume-Uni", social: 8, tax: 20, socialLabel: "Employee NI (%)", taxLabel: "Income tax (basic) (%)", note: "approx. PAYE" },
  { id: "US", name: "États-Unis", social: 7.65, tax: 12, socialLabel: "FICA (%)", taxLabel: "Federal tax (approx.) (%)", note: "sans state tax" },
  { id: "CA", name: "Canada", social: 7.5, tax: 15, socialLabel: "CPP/EI (approx.) (%)", taxLabel: "Income tax (%)", note: "varie par province" },
  { id: "MA", name: "Maroc", social: 6.7, tax: 10, socialLabel: "CNSS salarié (%)", taxLabel: "IR (%)", note: "approx." },
  { id: "AE", name: "Émirats (UAE)", social: 0, tax: 0, socialLabel: "Social (%)", taxLabel: "Income tax (%)", note: "souvent 0% pour salariés" },
  { id: "CUSTOM", name: "Personnalisé", social: 22, tax: 0, socialLabel: "Charges / social (%)", taxLabel: "Impôt (%)", note: "entre tes propres %" },
];
