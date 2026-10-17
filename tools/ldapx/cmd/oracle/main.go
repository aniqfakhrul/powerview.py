//go:debug randseednop=0

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"github.com/Macmod/ldapx/middlewares"
	attrentriesmid "github.com/Macmod/ldapx/middlewares/attrentries"
	attrlistmid "github.com/Macmod/ldapx/middlewares/attrlist"
	basednmid "github.com/Macmod/ldapx/middlewares/basedn"
	filtermid "github.com/Macmod/ldapx/middlewares/filter"
	"github.com/Macmod/ldapx/parser"
)

var anrSet = []string{
	"name", "displayname", "samaccountname",
	"givenname", "legacyexchangedn", "sn", "proxyaddresses",
	"physicaldeliveryofficename", "msds-additionalsamaccountName",
	"msds-phoneticcompanyname", "msds-phoneticdepartment",
	"msds-phoneticdisplayname", "msds-phoneticfirstname",
	"msds-phoneticlastname",
}

type Request struct {
	Kind    string            `json:"kind"`
	Chain   string            `json:"chain"`
	Input   string            `json:"input,omitempty"`
	Attrs   []string          `json:"attrs,omitempty"`
	Options map[string]string `json:"options,omitempty"`
	Seed    int64             `json:"seed"`
	N       int               `json:"n"`
}

type Response struct {
	Outputs []any  `json:"outputs,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Fixture struct {
	Revision   string              `json:"revision"`
	Samples    int                 `json:"samples"`
	Filters    []string            `json:"filters"`
	DNs        []string            `json:"dns"`
	AttrLists  [][]string          `json:"attr_lists"`
	Entries    []string            `json:"entries"`
	OptionSets []map[string]string `json:"option_sets"`
	Cases      [][]any             `json:"cases"`
	Renders    []string            `json:"renders"`
	Random     []RandomVector      `json:"random"`
}

type RandomVector struct {
	Seed    int64     `json:"seed"`
	Int63   []int64   `json:"int63"`
	Intn    [][2]int  `json:"intn"`
	Float64 []float64 `json:"float64"`
	Shuffle []int     `json:"shuffle"`
}

func randomVector(seed int64) RandomVector {
	rand.Seed(seed)
	v := RandomVector{Seed: seed}
	for range 4 {
		v.Int63 = append(v.Int63, rand.Int63())
	}
	for _, n := range []int{1, 2, 3, 10, 26, 607, 1 << 30, (1 << 31) - 1, 1 << 31, 4294967296, 1<<40 + 3} {
		v.Intn = append(v.Intn, [2]int{n, rand.Intn(n)})
	}
	for range 4 {
		v.Float64 = append(v.Float64, rand.Float64())
	}
	v.Shuffle = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	rand.Shuffle(len(v.Shuffle), func(i, j int) { v.Shuffle[i], v.Shuffle[j] = v.Shuffle[j], v.Shuffle[i] })
	return v
}

type opts map[string]string

func (o opts) str(k string) string {
	if v, ok := o[k]; ok {
		return v
	}
	return middlewares.DefaultOptions[k]
}

func (o opts) integer(k string) int {
	if v, err := strconv.Atoi(o[k]); err == nil {
		return v
	}
	v, _ := strconv.Atoi(middlewares.DefaultOptions[k])
	return v
}

func (o opts) float(k string) float64 {
	if v, err := strconv.ParseFloat(o[k], 64); err == nil {
		return v
	}
	v, _ := strconv.ParseFloat(middlewares.DefaultOptions[k], 64)
	return v
}

func (o opts) boolean(k string) bool { return strings.ToLower(o.str(k)) == "true" }

func filterMiddleware(c rune, o opts) filtermid.FilterMiddleware {
	switch c {
	case 'O':
		return filtermid.OIDAttributeFilterObf(o.integer("FiltOIDAttributeMaxSpaces"), o.integer("FiltOIDAttributeMaxZeros"), o.boolean("FiltOIDAttributeIncludePrefix"))
	case 'C':
		return filtermid.RandCaseFilterObf(o.float("FiltCaseProb"))
	case 'X':
		return filtermid.RandHexValueFilterObf(o.float("FiltHexValueProb"))
	case 'S':
		return filtermid.RandSpacingFilterObf(o.integer("FiltSpacingMaxSpaces"))
	case 'T':
		return filtermid.ReplaceTautologiesFilterObf()
	case 't':
		return filtermid.RandTimestampSuffixFilterObf(o.integer("FiltTimestampGarbageMaxChars"), o.str("FiltGarbageCharset"), o.boolean("FiltTimestampGarbageUseComma"))
	case 'B':
		return filtermid.RandAddBoolFilterObf(o.integer("FiltAddBoolMaxDepth"), o.float("FiltAddBoolProb"))
	case 'D':
		return filtermid.RandDblNegBoolFilterObf(o.integer("FiltDblNegBoolMaxDepth"), o.float("FiltDblNegBoolProb"))
	case 'M':
		return filtermid.DeMorganBoolFilterObf()
	case 'R':
		return filtermid.RandBoolReorderFilterObf()
	case 'b':
		return filtermid.ExactBitwiseBreakoutFilterObf()
	case 'd':
		return filtermid.BitwiseDecomposeFilterObf(o.integer("FiltBitwiseDecompositionMaxBits"))
	case 'I':
		return filtermid.EqualityByInclusionFilterObf()
	case 'E':
		return filtermid.EqualityByExclusionFilterObf()
	case 'G':
		return filtermid.RandGarbageFilterObf(o.integer("FiltGarbageMaxElems"), o.integer("FiltGarbageMaxSize"), o.str("FiltGarbageCharset"))
	case 'A':
		return filtermid.EqualityToApproxMatchFilterObf()
	case 'x':
		return filtermid.EqualityToExtensibleFilterObf(o.boolean("FiltEqExtensibleAppendDN"))
	case 'Z':
		return filtermid.RandPrependZerosFilterObf(o.integer("FiltPrependZerosMaxElems"))
	case 's':
		return filtermid.RandSubstringSplitFilterObf(o.float("FiltSubstringSplitProb"))
	case 'N':
		return filtermid.ANRAttributeFilterObf(anrSet)
	case 'n':
		return filtermid.ANRSubstringGarbageFilterObf(o.integer("FiltANRSubstringMaxElems"), o.str("FiltGarbageCharset"))
	case 'P':
		return filtermid.RandDNAttributesNoiseFilterObf(o.float("FiltDNAttrNoiseProb"))
	case 'L':
		return filtermid.TransitiveEvalFilterObf()
	case 'F':
		return filtermid.ObjectCategoryFormFilterObf(o.str("FiltObjCategoryRootDN"))
	case 'U':
		return filtermid.RandIgnorableUnicodeFilterObf(o.float("FiltIgnorableUnicodeProb"), o.str("FiltIgnorableUnicodeMode"))
	case 'W':
		return filtermid.RandAltSpaceFilterObf(o.float("FiltAltSpaceProb"), o.boolean("FiltAltSpaceIncludeVisible"))
	case 'K':
		return filtermid.RandSortKeyFoldFilterObf(o.float("FiltSortKeyFoldProb"), o.str("FiltSortKeyFoldClasses"))
	}
	return nil
}

func baseDNMiddleware(c rune, o opts) (string, basednmid.BaseDNMiddleware) {
	switch c {
	case 'O':
		return "OIDAttribute", basednmid.OIDAttributeBaseDNObf(o.integer("BDNOIDAttributeMaxSpaces"), o.integer("BDNOIDAttributeMaxZeros"), o.boolean("BDNOIDAttributeIncludePrefix"))
	case 'C':
		return "Case", basednmid.RandCaseBaseDNObf(o.float("BDNCaseProb"))
	case 'X':
		return "HexValue", basednmid.RandHexValueBaseDNObf(o.float("BDNHexValueProb"))
	case 'S':
		return "Spacing", basednmid.RandSpacingBaseDNObf(o.integer("BDNSpacingMaxElems"))
	case 'Q':
		return "DoubleQuotes", basednmid.DoubleQuotesBaseDNObf()
	case 'U':
		return "GUIDFormat", basednmid.GUIDBaseDNObf(o.str("BDNGuid"), o.str("BDNMatch"))
	case 'I':
		return "SIDFormat", basednmid.SIDBaseDNObf(o.str("BDNSid"), o.str("BDNMatch"))
	case 'W':
		return "WKGUIDFormat", basednmid.WKGUIDFormatBaseDNObf()
	case 'N':
		return "IgnorableUnicode", basednmid.RandIgnorableUnicodeBaseDNObf(o.float("BDNIgnorableUnicodeProb"), o.str("BDNIgnorableUnicodeMode"))
	case 'A':
		return "AltSpace", basednmid.RandAltSpaceBaseDNObf(o.float("BDNAltSpaceProb"), o.boolean("BDNAltSpaceIncludeVisible"))
	case 'K':
		return "SortKeyFold", basednmid.RandSortKeyFoldBaseDNObf(o.float("BDNSortKeyFoldProb"), o.str("BDNSortKeyFoldClasses"))
	}
	return "", nil
}

func attrListMiddleware(c rune, o opts) attrlistmid.AttrListMiddleware {
	switch c {
	case 'O':
		return attrlistmid.OIDAttributeAttrListObf(o.integer("AttrsOIDAttributeMaxSpaces"), o.integer("AttrsOIDAttributeMaxZeros"), o.boolean("AttrsOIDAttributeIncludePrefix"))
	case 'C':
		return attrlistmid.RandCaseAttrListObf(o.float("AttrsCaseProb"))
	case 'D':
		return attrlistmid.DuplicateAttrListObf(o.float("AttrsDuplicateProb"))
	case 'G':
		return attrlistmid.GarbageNonExistingAttrListObf(o.integer("AttrsGarbageNonExistingMaxElems"), o.integer("AttrsGarbageNonExistingMaxSize"), o.str("AttrsGarbageCharset"))
	case 'g':
		return attrlistmid.GarbageExistingAttrListObf(o.integer("AttrsGarbageExistingMaxElems"))
	case 'W':
		return attrlistmid.ReplaceWithWildcardAttrListObf()
	case 'w':
		return attrlistmid.AddWildcardAttrListObf()
	case 'p':
		return attrlistmid.AddPlusAttrListObf()
	case 'E':
		return attrlistmid.ReplaceWithEmptyAttrListObf()
	case 'R':
		return attrlistmid.ReorderListAttrListObf()
	case 'r':
		return attrlistmid.RangeAttrListObf(o.str("AttrsRangeOption"))
	}
	return nil
}

func attrEntriesMiddleware(c rune, o opts) attrentriesmid.AttrEntriesMiddleware {
	switch c {
	case 'O':
		return attrentriesmid.OIDAttributeAttrEntriesObf(o.integer("AttrEntriesOIDAttributeMaxSpaces"), o.integer("AttrEntriesOIDAttributeMaxZeros"), o.boolean("AttrEntriesOIDAttributeIncludePrefix"))
	case 'C':
		return attrentriesmid.RandCaseAttrEntriesObf(o.float("AttrEntriesCaseProb"))
	case 'R':
		return attrentriesmid.ReorderListAttrEntriesObf()
	}
	return nil
}

func hexString(s string) string { return hex.EncodeToString([]byte(s)) }

func hexList(items []string) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = hexString(item)
	}
	return out
}

func encodeFilter(f parser.Filter) map[string]any {
	switch v := f.(type) {
	case *parser.FilterAnd:
		return map[string]any{"type": "and", "filters": encodeFilters(v.Filters)}
	case *parser.FilterOr:
		return map[string]any{"type": "or", "filters": encodeFilters(v.Filters)}
	case *parser.FilterNot:
		return map[string]any{"type": "not", "filter": encodeFilter(v.Filter)}
	case *parser.FilterEqualityMatch:
		return map[string]any{"type": "equality", "attribute": hexString(v.AttributeDesc), "value": hexString(v.AssertionValue)}
	case *parser.FilterGreaterOrEqual:
		return map[string]any{"type": "greater_or_equal", "attribute": hexString(v.AttributeDesc), "value": hexString(v.AssertionValue)}
	case *parser.FilterLessOrEqual:
		return map[string]any{"type": "less_or_equal", "attribute": hexString(v.AttributeDesc), "value": hexString(v.AssertionValue)}
	case *parser.FilterApproxMatch:
		return map[string]any{"type": "approx", "attribute": hexString(v.AttributeDesc), "value": hexString(v.AssertionValue)}
	case *parser.FilterPresent:
		return map[string]any{"type": "present", "attribute": hexString(v.AttributeDesc)}
	case *parser.FilterSubstring:
		parts := make([][]string, len(v.Substrings))
		for i, s := range v.Substrings {
			parts[i] = []string{hexString(s.Initial), hexString(s.Any), hexString(s.Final)}
		}
		return map[string]any{"type": "substring", "attribute": hexString(v.AttributeDesc), "substrings": parts}
	case *parser.FilterExtensibleMatch:
		return map[string]any{"type": "extensible", "rule": hexString(v.MatchingRule), "attribute": hexString(v.AttributeDesc), "value": hexString(v.MatchValue), "dn": v.DNAttributes}
	}
	return nil
}

func encodeFilters(filters []parser.Filter) []any {
	out := make([]any, len(filters))
	for i, f := range filters {
		out[i] = encodeFilter(f)
	}
	return out
}

func run(r Request) (outputs []any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	o := opts(r.Options)
	n := max(r.N, 1)
	rand.Seed(r.Seed)
	switch r.Kind {
	case "filter":
		chain := &filtermid.FilterMiddlewareChain{}
		for _, c := range r.Chain {
			m := filterMiddleware(c, o)
			if m == nil {
				return nil, fmt.Errorf("unknown filter code %q", c)
			}
			chain.Add(filtermid.FilterMiddlewareDefinition{Name: string(c), Func: func() filtermid.FilterMiddleware { return m }})
		}
		for range n {
			f, err := parser.QueryToFilter(r.Input)
			if err != nil {
				return nil, err
			}
			outputs = append(outputs, encodeFilter(chain.Execute(f, false)))
		}
	case "basedn", "basedn_safe":
		chain := &basednmid.BaseDNMiddlewareChain{}
		for _, c := range r.Chain {
			name, m := baseDNMiddleware(c, o)
			if m == nil {
				return nil, fmt.Errorf("unknown basedn code %q", c)
			}
			chain.Add(basednmid.BaseDNMiddlewareDefinition{Name: name, Func: func() basednmid.BaseDNMiddleware { return m }})
		}
		for range n {
			if r.Kind == "basedn" {
				outputs = append(outputs, hexString(chain.Execute(r.Input, false)))
			} else {
				outputs = append(outputs, hexString(chain.ExecuteSafe(r.Input, false)))
			}
		}
	case "attrlist":
		chain := &attrlistmid.AttrListMiddlewareChain{}
		for _, c := range r.Chain {
			m := attrListMiddleware(c, o)
			if m == nil {
				return nil, fmt.Errorf("unknown attrlist code %q", c)
			}
			chain.Add(attrlistmid.AttrListMiddlewareDefinition{Name: string(c), Func: func() attrlistmid.AttrListMiddleware { return m }})
		}
		for range n {
			outputs = append(outputs, hexList(chain.Execute(append([]string{}, r.Attrs...), false)))
		}
	case "attrentries":
		chain := &attrentriesmid.AttrEntriesMiddlewareChain{}
		for _, c := range r.Chain {
			m := attrEntriesMiddleware(c, o)
			if m == nil {
				return nil, fmt.Errorf("unknown attrentries code %q", c)
			}
			chain.Add(attrentriesmid.AttrEntriesMiddlewareDefinition{Name: string(c), Func: func() attrentriesmid.AttrEntriesMiddleware { return m }})
		}
		for range n {
			var entries parser.AttrEntries
			for _, name := range r.Attrs {
				entries.AppendAttr(name, "v")
			}
			names := []string{}
			for _, entry := range chain.Execute(entries, false) {
				names = append(names, entry.Name)
			}
			outputs = append(outputs, hexList(names))
		}
	default:
		return nil, fmt.Errorf("unknown kind %q", r.Kind)
	}
	return outputs, nil
}

func serve() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		var r Request
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			encoder.Encode(Response{Error: err.Error()})
			continue
		}
		outputs, err := run(r)
		if err != nil {
			encoder.Encode(Response{Error: err.Error()})
			continue
		}
		encoder.Encode(Response{Outputs: outputs})
	}
}

func digest(outputs []any) string {
	canonical, err := json.Marshal(outputs)
	if err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:8])
}

func fixtures(path string, revision string) {
	fixture := Fixture{
		Revision:   revision,
		Samples:    samples,
		Filters:    allFilters(),
		DNs:        corpusDNs,
		AttrLists:  corpusAttrLists,
		Entries:    corpusEntries,
		OptionSets: optionSets(),
	}
	for _, f := range allFilters() {
		parsed, err := parser.QueryToFilter(f)
		if err != nil {
			log.Fatal(err)
		}
		rendered, err := parser.FilterToQuery(parsed)
		if err != nil {
			log.Fatal(err)
		}
		fixture.Renders = append(fixture.Renders, hexString(rendered))
	}
	for _, seed := range []int64{0, 1, -1, 42, -9223372036854775808} {
		fixture.Random = append(fixture.Random, randomVector(seed))
	}
	for _, c := range corpus() {
		outputs, err := run(c.request(fixture))
		if err != nil {
			log.Fatalf("%+v: %v", c, err)
		}
		fixture.Cases = append(fixture.Cases, []any{c.kind, c.chain, c.input, c.options, c.seed, digest(outputs)})
	}
	data, err := json.Marshal(fixture)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d cases to %s", len(fixture.Cases), path)
}

func main() {
	out := flag.String("fixtures", "", "write the deterministic parity corpus to this path instead of serving JSON lines")
	revision := flag.String("revision", "", "upstream revision recorded in the fixture")
	flag.Parse()
	if *out != "" {
		fixtures(*out, *revision)
		return
	}
	serve()
}
