package sbom

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/attestation"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/sbom/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Format string

const (
	FormatCycloneDXJSON       Format = "cyclonedx-json"
	FormatCycloneDXXML        Format = "cyclonedx-xml"
	FormatSPDXJSON            Format = "spdx-json"
	FormatSPDXTV              Format = "spdx-tv"
	FormatSPDXXML             Format = "spdx-xml"
	FormatAttestCycloneDXJSON Format = "attest-cyclonedx-json"
	FormatAttestSPDXJSON      Format = "attest-spdx-json"
	FormatUnknown             Format = "unknown"

	// FormatSigstoreBundleCycloneDXJSON is used for Sigstore bundle format containing CycloneDX SBOM attestation.
	// This format is produced by Cosign v3+ with the new bundle format.
	// ref. https://github.com/sigstore/cosign/blob/main/specs/BUNDLE_SPEC.md
	FormatSigstoreBundleCycloneDXJSON Format = "sigstore-bundle-cyclonedx-json"

	// FormatSigstoreBundleSPDXJSON is used for Sigstore bundle format containing SPDX SBOM attestation.
	FormatSigstoreBundleSPDXJSON Format = "sigstore-bundle-spdx-json"

	// FormatLegacyCosignAttestCycloneDXJSON is used to support the older format of CycloneDX JSON Attestation
	// produced by the Cosign V1.
	// ref. https://github.com/sigstore/cosign/pull/2718
	FormatLegacyCosignAttestCycloneDXJSON Format = "legacy-cosign-attest-cyclonedx-json"

	// PredicateCycloneDXBeforeV05 is the PredicateCycloneDX value defined in in-toto-golang before v0.5.0.
	// This is necessary for backward-compatible SBOM detection.
	// ref. https://github.com/in-toto/in-toto-golang/pull/188
	PredicateCycloneDXBeforeV05 = "https://cyclonedx.org/schema"

	// SigstoreBundleMediaType is the media type for Sigstore bundles v0.3
	// ref. https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
	SigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

var ErrUnknownFormat = xerrors.New("Unknown SBOM format")

type cdxHeader struct {
	// XML specific field
	XMLNS string `json:"-" xml:"xmlns,attr"`

	// JSON specific field
	BOMFormat string `json:"bomFormat" xml:"-"`
}

type spdxHeader struct {
	SpdxID string `json:"SPDXID"`
}

// sigstoreBundle represents the structure of a Sigstore bundle
// ref. https://github.com/sigstore/cosign/blob/main/specs/BUNDLE_SPEC.md
type sigstoreBundle struct {
	MediaType    string          `json:"mediaType"`
	DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
}

// matchesHeader rewinds the reader and reports whether its content matches
// the given format check.
func matchesHeader(r io.ReadSeeker, match func(io.Reader) bool) (bool, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return false, xerrors.Errorf("seek error: %w", err)
	}
	return match(r), nil
}

func IsCycloneDXJSON(r io.ReadSeeker) (bool, error) {
	return matchesHeader(r, func(r io.Reader) bool {
		var cdxBom cdxHeader
		return json.NewDecoder(r).Decode(&cdxBom) == nil && cdxBom.BOMFormat == "CycloneDX"
	})
}

func IsCycloneDXXML(r io.ReadSeeker) (bool, error) {
	return matchesHeader(r, func(r io.Reader) bool {
		var cdxBom cdxHeader
		return xml.NewDecoder(r).Decode(&cdxBom) == nil && strings.HasPrefix(cdxBom.XMLNS, "http://cyclonedx.org")
	})
}

func IsSPDXJSON(r io.ReadSeeker) (bool, error) {
	return matchesHeader(r, func(r io.Reader) bool {
		var spdxBom spdxHeader
		return json.NewDecoder(r).Decode(&spdxBom) == nil && spdxBom.SpdxID == "SPDXRef-DOCUMENT"
	})
}

func IsSPDXTV(r io.ReadSeeker) (bool, error) {
	return matchesHeader(r, func(r io.Reader) bool {
		scanner := bufio.NewScanner(r)
		return scanner.Scan() && strings.HasPrefix(scanner.Text(), "SPDX")
	})
}

func DetectFormat(r io.ReadSeeker) (Format, error) {
	// Rewind the SBOM file at the end
	defer r.Seek(0, io.SeekStart)

	formatChecks := []struct {
		isFormat func(io.ReadSeeker) (bool, error)
		format   Format
	}{
		{IsCycloneDXJSON, FormatCycloneDXJSON},
		{IsCycloneDXXML, FormatCycloneDXXML},
		{IsSPDXJSON, FormatSPDXJSON},
		{IsSPDXTV, FormatSPDXTV},
	}
	for _, c := range formatChecks {
		if ok, err := c.isFormat(r); err != nil {
			return FormatUnknown, err
		} else if ok {
			return c.format, nil
		}
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return FormatUnknown, xerrors.Errorf("seek error: %w", err)
	}

	// Try in-toto attestation (CycloneDX or SPDX)
	format, ok := decodeAttestationFormat(r)
	if ok {
		return format, nil
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return FormatUnknown, xerrors.Errorf("seek error: %w", err)
	}

	// Try Sigstore bundle
	format, ok = decodeSigstoreBundleFormat(r)
	if ok {
		return format, nil
	}

	return FormatUnknown, nil
}

func decodeAttestationFormat(r io.ReadSeeker) (Format, bool) {
	var s attestation.Statement

	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return "", false
	}

	if s.Predicate == nil {
		return "", false
	}

	m, ok := s.Predicate.(map[string]any)
	if !ok {
		return "", false
	}

	// Check CycloneDX
	if s.PredicateType == in_toto.PredicateCycloneDX || s.PredicateType == PredicateCycloneDXBeforeV05 {
		if _, ok := m["Data"]; ok {
			return FormatLegacyCosignAttestCycloneDXJSON, true
		}
		return FormatAttestCycloneDXJSON, true
	}

	// Check SPDX
	if s.PredicateType == in_toto.PredicateSPDX {
		if spdxID, ok := m["SPDXID"].(string); ok && spdxID == "SPDXRef-DOCUMENT" {
			return FormatAttestSPDXJSON, true
		}
	}

	return "", false
}

func decodeSigstoreBundleFormat(r io.ReadSeeker) (Format, bool) {
	var bundle sigstoreBundle
	if err := json.NewDecoder(r).Decode(&bundle); err != nil {
		return "", false
	}

	// Check if the media type indicates a Sigstore bundle
	if bundle.MediaType != SigstoreBundleMediaType {
		return "", false
	}

	if bundle.DSSEEnvelope == nil {
		return "", false
	}

	// Parse the DSSE envelope to determine the SBOM format
	var s attestation.Statement
	if err := json.Unmarshal(bundle.DSSEEnvelope, &s); err != nil {
		return "", false
	}

	if s.Predicate == nil {
		return "", false
	}

	switch s.PredicateType {
	case in_toto.PredicateCycloneDX, PredicateCycloneDXBeforeV05:
		return FormatSigstoreBundleCycloneDXJSON, true
	case in_toto.PredicateSPDX:
		return FormatSigstoreBundleSPDXJSON, true
	}

	return "", false
}

func Decode(ctx context.Context, f io.Reader, format Format) (types.SBOM, error) {
	var (
		v       any
		bom     *core.BOM
		decoder interface{ Decode(any) error }
	)

	switch format {
	case FormatCycloneDXJSON:
		bom = core.NewBOM(core.Options{GenerateBOMRef: true})
		v = &cyclonedx.BOM{BOM: bom}
		decoder = json.NewDecoder(f)
	case FormatAttestCycloneDXJSON:
		// dsse envelope
		//   => in-toto attestation
		//     => CycloneDX JSON
		bom = core.NewBOM(core.Options{GenerateBOMRef: true})
		v = &attestation.Statement{
			Predicate: &cyclonedx.BOM{BOM: bom},
		}
		decoder = json.NewDecoder(f)
	case FormatLegacyCosignAttestCycloneDXJSON:
		// dsse envelope
		//   => in-toto attestation
		//     => cosign predicate
		//       => CycloneDX JSON
		bom = core.NewBOM(core.Options{GenerateBOMRef: true})
		v = &attestation.Statement{
			Predicate: &attestation.CosignPredicate{
				Data: &cyclonedx.BOM{BOM: bom},
			},
		}
		decoder = json.NewDecoder(f)
	case FormatAttestSPDXJSON:
		// dsse envelope
		//   => in-toto attestation
		//     => SPDX JSON
		bom = core.NewBOM(core.Options{})
		v = &attestation.Statement{
			Predicate: &spdx.SPDX{BOM: bom},
		}
		decoder = json.NewDecoder(f)
	case FormatSigstoreBundleCycloneDXJSON:
		// Sigstore bundle
		//   => dsse envelope
		//     => in-toto attestation
		//       => CycloneDX JSON
		bom = core.NewBOM(core.Options{GenerateBOMRef: true})
		v = &attestation.SigstoreBundle{
			DSSEEnvelope: attestation.Statement{
				Predicate: &cyclonedx.BOM{BOM: bom},
			},
		}
		decoder = json.NewDecoder(f)
	case FormatSigstoreBundleSPDXJSON:
		// Sigstore bundle
		//   => dsse envelope
		//     => in-toto attestation
		//       => SPDX JSON
		bom = core.NewBOM(core.Options{})
		v = &attestation.SigstoreBundle{
			DSSEEnvelope: attestation.Statement{
				Predicate: &spdx.SPDX{BOM: bom},
			},
		}
		decoder = json.NewDecoder(f)
	case FormatSPDXJSON:
		bom = core.NewBOM(core.Options{})
		v = &spdx.SPDX{BOM: bom}
		decoder = json.NewDecoder(f)
	case FormatSPDXTV:
		bom = core.NewBOM(core.Options{})
		v = &spdx.SPDX{BOM: bom}
		decoder = spdx.NewTVDecoder(f)
	default:
		return types.SBOM{}, xerrors.Errorf("%s scanning is not yet supported", format)

	}

	// Decode a file content into core.BOM
	if err := decoder.Decode(v); err != nil {
		return types.SBOM{}, xerrors.Errorf("failed to decode: %w", err)
	}

	var sbom types.SBOM
	if err := sbomio.NewDecoder(bom).Decode(ctx, &sbom); err != nil {
		return types.SBOM{}, xerrors.Errorf("failed to decode: %w", err)
	}

	return sbom, nil
}
