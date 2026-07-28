// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	base: '/docs/guide',
	integrations: [
		starlight({
			title: 'R.O.V.E.R. Documentation',
			description: 'Official user guide, architecture, and feature documentation for R.O.V.E.R. Security & Release Management.',
			social: [
				{ icon: 'github', label: 'GitHub Repository', href: 'https://github.com/kajuberdut/ROVER' }
			],
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Overview', slug: 'getting-started/overview' },
						{ label: 'Quickstart Guide', slug: 'getting-started/quickstart' },
					],
				},
				{
					label: 'User Guides & Features',
					items: [
						{ label: 'Multi-Scanner Engine (Trivy, Semgrep, Snyk)', slug: 'guides/scanners' },
						{ label: 'Automated Scan Scheduler', slug: 'guides/scheduled-scans' },
						{ label: 'OpenBao Credential Vault', slug: 'guides/vault-credentials' },
						{ label: 'Vulnerability Reports & Deep-Linking', slug: 'guides/reports' },
					],
				},
				{
					label: 'API & Integrations',
					items: [
						{ label: 'Public REST API & OpenAPI', slug: 'api/public-api' },
						{ label: 'CI/CD Pipeline Ingestion', slug: 'api/ci-cd-pipelines' },
					],
				},
				{
					label: 'Project Updates',
					items: [
						{ label: 'Changelog', slug: 'changelog' },
						{ label: 'Product Roadmap', slug: 'roadmap' },
					],
				},
			],
		}),
	],
});
