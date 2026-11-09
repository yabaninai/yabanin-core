-- R108-02 (ratified minimal scope 2026-10-16 «облачные по-минимуму»):
-- Azure OpenAI FIRST — chk_provider gains 'azure-openai' (Entra ID auth,
-- deployment-qualified URLs; adapter pkg/provider/azure_openai.go).
-- Bedrock/Vertex get provider_jurisdictions SEED ROWS ONLY (registry stubs
-- for the follow-up cards R108-03/04) — they are deliberately NOT added to
-- chk_provider: configuring models_registry rows for adapter-less providers
-- would promise support the factory explicitly refuses
-- (provider.New("bedrock") errors — "unsupported не обещан").
--
-- provider_jurisdictions values (D6 2026-10-16: residency = страна, the
-- existing models_registry.region semantics enforced by the policy Enforcer
-- — untouched by this migration):
--   corp_country = vendor HQ (Microsoft/Amazon/Google = US);
--   default_inference_region = conservative fallback for the lineage
--   resolver when neither a pinned region nor response headers disclose the
--   serving country (US, consistent with the fail-closed default);
--   data_center_regions = known DC countries (JP documented by the
--   asia_packs/jp policy: Azure Japan East / Bedrock ap-northeast-1).

ALTER TABLE public.models_registry DROP CONSTRAINT chk_provider;
ALTER TABLE public.models_registry
    ADD CONSTRAINT chk_provider CHECK ((provider = ANY (ARRAY['openai'::text, 'openai-compat'::text, 'anthropic'::text, 'custom'::text, 'vllm'::text, 'ollama'::text, 'tgi'::text, 'sakana'::text, 'sarvam'::text, 'krutrim'::text, 'naver'::text, 'falcon'::text, 'jais'::text, 'mistral'::text, 'yandex'::text, 'sber'::text, 'llamacpp'::text, 'zai-coding'::text, 'azure-openai'::text])));

INSERT INTO public.provider_jurisdictions (provider, corp_country, default_inference_region, data_center_regions, notes) VALUES
    ('azure-openai', 'US', 'US', '{US,EU,JP}', 'R108-02: Azure OpenAI, Entra ID client-credentials; JSON secret per org credential; residency = models_registry.region country (D2/D4/D6 2026-10-16)'),
    ('bedrock', 'US', 'US', '{US,EU,JP}', 'R108 registry stub only — NO adapter yet (R108-03); chk_provider intentionally unchanged for bedrock'),
    ('vertex', 'US', 'US', '{US,EU,JP}', 'R108 registry stub only — NO adapter yet (R108-04); chk_provider intentionally unchanged for vertex');
