package cli

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"crypto/ed25519"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/lineage"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// attachLineage signs a per-request lineage attestation and appends it to the ledger.
// It also stamps the event with jurisdictional fields for downstream observability.
// Best-effort: failures are logged but never block the request path.
// finalInfo should be the *winning* model info (post-fallback) so jurisdictional
// fields reflect the actual provider/region that served this request.
func (gw *gateway) attachLineage(ctx context.Context, orgID, reqID, finalModelName string, finalInfo resolver.ModelInfo, resp *http.Response, ev *eventpub.Event, l *slog.Logger) {
	if gw.lineageKeyStore == nil || gw.lineageKeys == nil || gw.lineageLedgerStore == nil || gw.lineageAsync == nil || orgID == "" {
		return
	}

	// Region evidence: the registry-declared region of the winning model is
	// endpoint-pinned knowledge (we chose the destination); when it is empty
	// or GLOBAL the claim degrades to the provider's declared default. Real
	// header evidence requires wiring the upstream *http.Response through the
	// call sites (follow-up).
	region, evidence := gw.regionResolver.ResolveInferenceRegionWithEvidence(
		ctx, finalInfo.Provider, finalInfo.UpstreamURL, finalInfo.Region, resp)

	att := lineage.Attestation{
		RequestID:        reqID,
		OrgID:            orgID,
		Timestamp:        time.Now().UTC().Format(time.RFC3339Nano),
		ModelUsed:        finalModelName,
		InferenceRegion:  region,
		ModelOrigin:      finalInfo.Provider,
		LogStorageRegion: gw.cfg.Region,
		ProviderEntity:   finalInfo.Provider,
		RegionEvidence:   string(evidence),
	}

	keyID, _, privBytes, keyErr := gw.lineageKeys.EnsureKeyPair(ctx, orgID)
	if keyErr != nil {
		l.Warn("lineage key retrieval failed", "error", keyErr)
		return
	}

	signer, signErr := lineage.NewSigner(keyID, ed25519.PrivateKey(privBytes))
	if signErr != nil {
		l.Warn("lineage signer creation failed", "error", signErr)
		return
	}

	hash, hashErr := att.Hash()
	if hashErr != nil {
		l.Warn("lineage hash computation failed", "error", hashErr)
		return
	}

	_, sigB64, sigErr := signer.Sign(hash)
	if sigErr != nil {
		l.Warn("lineage sign failed", "error", sigErr)
		return
	}

	if appendErr := gw.lineageAsync.Append(ctx, att, sigB64, keyID); appendErr != nil {
		l.Warn("failed to append lineage ledger", "error", appendErr)
		return
	}

	l.Debug("lineage attestation committed", "request_id", reqID, "key_id", keyID)

	// Stamp event with real attestation fields.
	if ev != nil {
		ev.InferenceRegion = att.InferenceRegion
		ev.RegionEvidence = att.RegionEvidence
		ev.ModelOriginCountry = att.ModelOrigin
		ev.LogStorageRegion = att.LogStorageRegion
		ev.ProviderEntityJurisdiction = att.ProviderEntity
	}
}
