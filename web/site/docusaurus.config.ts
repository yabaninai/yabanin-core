import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';

const config: Config = {
  title: 'Yabanin',
  tagline:
    'Your Agnostic Bridge Across Numerous Inference Networks — a self-hosted AI gateway: know your spend, control your requests.',
  favicon: 'img/favicon.svg',

  url: 'https://yabanin.ai',
  baseUrl: '/',
  trailingSlash: false,

  organizationName: 'yabaninai',
  projectName: 'yabanin-core',

  // PostHog analytics: cookieless pageviews + explicit CTA
  // events only. Privacy posture: no cookies (persistence memory), no
  // autocapture, no session recording, Do-Not-Track respected.
  //
  // without YABANIN_SITE_POSTHOG_KEY (the default, and every self-hosted
  // build of this repo) ships NO snippet and makes zero external requests —
  // self-hosted must not phone home. The hosted marketing deployment injects
  // its key via deploy env, outside this repository.
  headTags: process.env.YABANIN_SITE_POSTHOG_KEY
    ? [
        {
          tagName: 'script',
          attributes: {},
          innerHTML: `    !function(t,e){var o,n,p,r;e.__SV||(window.posthog=e,e._i=[],e.init=function(i,s,a){function g(t,e){var o=e.split(".");2==o.length&&(t=t[o[0]],e=o[1]),t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}}(p=t.createElement("script")).type="text/javascript",p.crossOrigin="anonymous",p.async=!0,p.src=s.api_host.replace(".i.posthog.com","-assets.i.posthog.com")+"/static/array.js",(r=t.getElementsByTagName("script")[0]).parentNode.insertBefore(p,r);var u=e;for(void 0!==a?u=e[a]=[]:a="posthog",u.people=u.people||[],Object.defineProperty(u,"toString",{configurable:!0,enumerable:!0,writable:!0,value:function(t){var e="posthog";return"posthog"!==a&&(e+="."+a),t||(e+=" (stub)"),e}}),Object.defineProperty(u.people,"toString",{configurable:!0,enumerable:!0,writable:!0,value:function(){return u.toString(1)+".people (stub)"}}),o="init capture register register_once register_for_sessionbar unregister getFeatureFlag getFeatureFlagResult isFeatureEnabled reloadFeatureFlags updateEarlyAccessFeatureEnrollment getEarlyAccessFeatures on onFeatureFlags onSessionId getSurveys getActiveMatchingSurveys renderSurvey canRenderSurvey getNextSurveyStep identify setPersonProperties group resetGroups setPersonPropertiesForFlags resetPersonPropertiesForFlags setGroupPropertiesForFlags resetGroupPropertiesForFlags reset get_distinct_id getGroups get_session_id get_session_replay_url alias set_config startSessionRecording stopSessionRecording sessionRecordingStarted captureException loadToolbar get_property getSessionProperty createPersonProfile opt_in_capturing opt_out_capturing has_opted_in_capturing has_opted_out_capturing clear_opt_in_out_capturing debug".split(" "),n=0;n<o.length;n++)g(u,o[n]);e._i.push([i,s,a])},e.__SV=1)}(document,window.posthog||[]);
    posthog.init('${String(process.env.YABANIN_SITE_POSTHOG_KEY)}', {
        api_host: '${String(process.env.YABANIN_SITE_POSTHOG_HOST || 'https://us.i.posthog.com')}',
        autocapture: false,
        capture_pageview: true,
        persistence: 'memory',
        respect_dnt: true,
        disable_session_recording: true,
        disable_survey: true,
        capture_performance: false,
    })`,
        },
      ]
    : [],

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          path: '../../docs',
          routeBasePath: 'docs',
          sidebarPath: './sidebars.ts',
          exclude: ['strategy/**'],
          showLastUpdateTime: true,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      },
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'light',
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    image: 'img/emblem.png',
    navbar: {
      title: 'Yabanin',
      logo: {
        alt: 'Yabanin',
        src: 'img/emblem.png',
        srcDark: 'img/emblem.png',
      },
      items: [
        {to: '/docs/quickstart', label: 'Quickstart', position: 'left'},
        {to: '/docs/onprem/install-guide', label: 'Deploy', position: 'left'},
        {to: '/docs/intro', label: 'Docs', position: 'left'},
        {
          href: 'mailto:sales@yabanin.ai',
          label: 'Contact sales',
          position: 'right',
        },
        {
          to: '/docs/quickstart',
          label: 'Get started',
          position: 'right',
          className: 'navbar-cta',
        },
      ],
    },
    footer: {
      style: 'light',
      links: [
        {
          title: 'Start',
          items: [
            {label: 'Offline audit', to: '/docs/audit'},
            {label: 'Local quickstart', to: '/docs/quickstart'},
            {label: 'Introduction', to: '/docs/intro'},
          ],
        },
        {
          title: 'Control',
          items: [
            {label: 'Lineage', to: '/docs/lineage'},
            {label: 'Residency packs', to: '/docs/residency-packs'},
            {label: 'Air-gap install', to: '/docs/onprem/install-guide'},
            {label: 'Shadow mode', to: '/docs/shadow-mode'},
          ],
        },
        {
          title: 'Talk',
          items: [
            {label: 'sales@yabanin.ai', href: 'mailto:sales@yabanin.ai'},
            {
              label: 'Dmitry Lakhvich on LinkedIn',
              href: 'https://www.linkedin.com/in/dmitry-lakhvich/',
            },
          ],
        },
      ],
      copyright: `© ${new Date().getFullYear()} Yabanin — Your Agnostic Bridge Across Numerous Inference Networks.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.github,
      additionalLanguages: ['bash', 'json', 'yaml', 'go'],
    },
  },
};

export default config;
