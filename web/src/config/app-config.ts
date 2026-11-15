import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Ripple",
  version: packageJson.version,
  copyright: `© ${currentYear}, Ripple. Based on ARTEX.`,
  meta: {
    title: "Ripple — Android Application Security Testing",
    description: "Scope, APK-to-API mapping, evidence-based coverage planning, and controlled security assessment",
  },
};
