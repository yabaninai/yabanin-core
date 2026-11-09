-- R108-02 down: restore the 18-value chk_provider and remove the cloud
-- provider jurisdiction seed rows (azure-openai / bedrock / vertex).

DELETE FROM public.provider_jurisdictions
    WHERE provider IN ('azure-openai', 'bedrock', 'vertex');

ALTER TABLE public.models_registry DROP CONSTRAINT chk_provider;
ALTER TABLE public.models_registry
    ADD CONSTRAINT chk_provider CHECK ((provider = ANY (ARRAY['openai'::text, 'openai-compat'::text, 'anthropic'::text, 'custom'::text, 'vllm'::text, 'ollama'::text, 'tgi'::text, 'sakana'::text, 'sarvam'::text, 'krutrim'::text, 'naver'::text, 'falcon'::text, 'jais'::text, 'mistral'::text, 'yandex'::text, 'sber'::text, 'llamacpp'::text, 'zai-coding'::text])));
