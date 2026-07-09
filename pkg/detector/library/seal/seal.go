package seal

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

// Seal Security appends an ecosystem-specific patch-level suffix to the upstream
// version of a no-prefix package. Each ecosystem uses its own separator, so the
// suffix is matched per ecosystem rather than with a single shared pattern.
//
// Both public ("spN") and private ("spNpM") sealed versions are matched: a
// private version carries an extra "pM" iteration on top of the sealed version
// (e.g. "2.7.4-sp2p1"). See
// https://docs.sealsecurity.io/reference/naming-and-versioning/sp-model and
// https://docs.sealsecurity.io/reference/naming-and-versioning/per-ecosystem
var (
	// Maven and PyPI: "$version+spN[pM]" (e.g. "9.4.48+sp1", "4.2.8+sp1p1").
	plusSealSuffix = regexp.MustCompile(`\+sp\d+(?:p\d+)?$`)
	// npm: "$version-spN[pM]" (e.g. "3.1.8-sp1", "3.1.8-sp1p1").
	npmSealSuffix = regexp.MustCompile(`-sp\d+(?:p\d+)?$`)
	// Go: "$version-spN[pM]", optionally followed by the "+incompatible" build
	// metadata Go adds to major-version-2+ modules without a /vN path
	// (e.g. "v1.1.1-sp1", "v2.0.0-sp1p1+incompatible").
	goSealSuffix = regexp.MustCompile(`-sp\d+(?:p\d+)?(?:\+incompatible)?$`)
	// RubyGems: "$version.0.1.spN[pM]" (e.g. "2.0.7.0.1.sp1", "2.0.7.0.1.sp1p1").
	rubySealSuffix = regexp.MustCompile(`\.0\.1\.sp\d+(?:p\d+)?$`)
)

func init() {
	library.RegisterVendor(sealSecurity{
		pipComparer: pep440.NewComparer(pep440.AllowLocalSpecifier()),
	})
}

// sealSecurity matches packages patched by Seal Security.
// Seal Security provides patched versions of open source packages with their own
// vulnerability advisories. Seal ships packages under two naming schemes:
//
// Renamed packages carry an ecosystem-specific name prefix:
//   - Maven:   seal.sp*.$groupId:$artifactId (e.g. seal.sp1, seal.sp2)
//   - npm:     @seal-security/$name
//   - Python:  seal-$name
//   - Go:      sealsecurity.io/$name
//   - Ruby:    seal-$name
//
// No-prefix packages keep the upstream name and only add a version suffix
// (e.g. "+sp1"/"-sp1"/".sp1"). They are detected by that suffix:
//   - Maven/PyPI: the "+spN" suffix cannot collide with real versions, so a
//     suffix match is authoritative (Matched).
//   - Go/npm/Ruby: the "-spN"/".spN" suffix can also appear on real packages,
//     so a suffix match is only a Candidate, confirmed against the Seal
//     advisory bucket (see library.Driver.advisories).
//
// See also: pkg/detector/ospkg/seal/ for the OS package equivalent.
type sealSecurity struct {
	pipComparer compare.Comparer
}

func (sealSecurity) Name() string {
	return "seal"
}

// ecosystemRule describes how sealed packages are detected in one ecosystem:
// a renamed-package name check and a no-prefix version-suffix pattern.
type ecosystemRule struct {
	// matchName reports whether the package name carries the ecosystem's
	// renamed-package prefix. A name match is always authoritative (Matched).
	matchName func(pkgName string) bool
	// versionSuffix matches the ecosystem's sealed version suffix.
	versionSuffix *regexp.Regexp
	// suffixResult is returned on a version-suffix match: Matched where the
	// suffix cannot collide with real versions (Maven/PyPI), Candidate where
	// it can and must be confirmed against the Seal advisory bucket
	// (Go/npm/Ruby).
	suffixResult library.MatchResult
}

var ecosystemRules = map[ecosystem.Type]ecosystemRule{
	ecosystem.Maven: {
		// Renamed: e.g. seal.sp1.org.eclipse.jetty:jetty-http
		matchName: func(pkgName string) bool {
			rest, ok := strings.CutPrefix(pkgName, "seal.sp")
			return ok && rest != "" && unicode.IsDigit(rune(rest[0]))
		},
		versionSuffix: plusSealSuffix,
		suffixResult:  library.Matched,
	},
	ecosystem.Pip: {
		// Renamed: e.g. seal-django
		matchName:     hasNamePrefix("seal-"),
		versionSuffix: plusSealSuffix,
		suffixResult:  library.Matched,
	},
	ecosystem.Npm: {
		// Renamed: e.g. @seal-security/ejs
		matchName:     hasNamePrefix("@seal-security/"),
		versionSuffix: npmSealSuffix,
		suffixResult:  library.Candidate,
	},
	ecosystem.Go: {
		// Renamed: e.g. sealsecurity.io/github.com/Masterminds/goutils
		matchName:     hasNamePrefix("sealsecurity.io/"),
		versionSuffix: goSealSuffix,
		suffixResult:  library.Candidate,
	},
	ecosystem.RubyGems: {
		// Renamed: e.g. seal-rack
		matchName:     hasNamePrefix("seal-"),
		versionSuffix: rubySealSuffix,
		suffixResult:  library.Candidate,
	},
}

func hasNamePrefix(prefix string) func(string) bool {
	return func(pkgName string) bool {
		return strings.HasPrefix(pkgName, prefix)
	}
}

// Match determines whether a package is provided by Seal Security.
// It expects a normalized package name (see vulnerability.NormalizePkgName).
func (sealSecurity) Match(eco ecosystem.Type, pkgName, pkgVer string) library.MatchResult {
	rule, ok := ecosystemRules[eco]
	if !ok {
		return library.NoMatch
	}
	if rule.matchName(pkgName) {
		return library.Matched
	}
	if rule.versionSuffix.MatchString(pkgVer) {
		return rule.suffixResult
	}
	return library.NoMatch
}

// BucketPrefix returns the vendor-specific advisory bucket prefix.
func (s sealSecurity) BucketPrefix(eco ecosystem.Type) string {
	return fmt.Sprintf("%s %s::", s.Name(), eco)
}

// Comparer returns a version comparer for the given ecosystem.
// For pip (Python), it enables local version specifiers to correctly handle
// Seal Security version suffixes (e.g. "4.2.8+sp1").
// For other ecosystems, it returns the default comparer unchanged.
func (s sealSecurity) Comparer(eco ecosystem.Type, defaultComparer compare.Comparer) compare.Comparer {
	if eco == ecosystem.Pip {
		return s.pipComparer
	}
	return defaultComparer
}
