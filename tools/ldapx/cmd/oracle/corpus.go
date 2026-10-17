package main

import "strings"

var seeds = []int64{1, -7}

const samples = 4

var corpusFilters = []string{
	`(&(samAccountType=805306368)(|(sAMAccountName=Administrator)(name=Administrator)(cn=Administrator)))`,
	`(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))`,
	`(objectSid=S-1-5-21-1275038127-4001443720-2863730958-512)`,
	`(&(objectClass=group)(memberOf=CN=Domain Admins,CN=Users,DC=wonka,DC=lab))`,
	`(&(objectClass=user)(whenCreated>=20240101000000.0Z)(whenChanged<=20250101000000,5+0100))`,
	`(|(cn=Adm*str*tor)(cn=*ss*)(displayName=*end))`,
	`(&(samAccountType=805306368)(servicePrincipalName=*)(!(cn=krbtgt)))`,
	`(&(userAccountControl=512)(groupType=-2147483646)(primaryGroupID=513))`,
	`(&(cn=Domain Admins)(description=Caf\c3\a9 cr\c3\a8me ffi))`,
	`(&(member:1.2.840.113556.1.4.1941:=CN=x,DC=y)(cn:dn:=z)(:dn:2.4.6.8:=w))`,
	`(&(aNR==jdoe)(aNR>=a)(sn~=Smith)(manager=CN=Boss,OU=People,DC=wonka,DC=lab))`,
	`(&(objectCategory=user)(objectCategory=CN=Computer,CN=Schema,CN=Configuration,DC=wonka,DC=lab))`,
	`(&(instanceType<=4)(msDS-SupportedEncryptionTypes>=24)(nonexistentattr=abc))`,
}

var filterChains = []string{
	"O", "C", "X", "S", "t", "B", "D", "M", "R", "b", "d", "I", "E", "G", "A", "x", "Z", "s", "N", "n", "P", "L", "F", "U", "W", "K",
	"CZNDR", "OCXSZtsB", "NnS", "bdP", "IEZC", "xPd", "UWKC", "sKCU", "GDRM", "LRx",
}

// Middlewares that rebuild a value rune by rune replace invalid UTF-8 bytes with
// U+FFFD upstream; the port preserves those bytes, so binary inputs skip them.
const runeRebuildingCodes = "CsIEUWK"

var binaryFilters = []string{
	`(&(objectGUID=\a1\b2\c3\d4\00\ff)(objectSid=\01\05\00\00\00\00\00\05\15\00\00\00\2d\30\39)(cn=\e9t\e9))`,
}

var filterOptionSets = []map[string]string{
	nil,
	{
		"FiltCaseProb":                    "1",
		"FiltIgnorableUnicodeMode":        "all",
		"FiltIgnorableUnicodeProb":        "0.9",
		"FiltAltSpaceIncludeVisible":      "true",
		"FiltSortKeyFoldClasses":          "width,enclosed,ligatures",
		"FiltSortKeyFoldProb":             "1",
		"FiltEqExtensibleAppendDN":        "true",
		"FiltSubstringSplitProb":          "1",
		"FiltGarbageCharset":              "\u00e9z",
		"FiltBitwiseDecompositionMaxBits": "3",
	},
}

var corpusDNs = []string{
	"DC=wonka,DC=lab",
	"CN=Users,DC=wonka,DC=lab",
	"OU=Domain Controllers,DC=wonka,DC=lab",
	"CN=Microsoft,CN=Program Data,DC=wonka,DC=lab",
	"cn=domain admins,cn=users,dc=wonka,dc=lab",
	"CN=Jos\u00e9 M\u00fcller,OU=Caf\u00e9 People,DC=wonka,DC=lab",
	"CN=a\\,b,CN=Trailing ,DC=wonka,DC=lab",
	"<WKGUID=a9d1ca15768811d1aded00c04fd8d5cd,DC=wonka,DC=lab>",
	"<GUID=00112233445566778899aabbccddeeff>",
	"",
}

var baseDNChains = []string{"O", "C", "X", "S", "Q", "W", "N", "A", "K", "CX", "WCX", "CWX", "QC", "XS", "OSC", "NAK", "U", "I"}

var baseDNOptions = map[string]string{
	"BDNGuid":                   "00112233445566778899aabbccddeeff",
	"BDNSid":                    "S-1-5-21-1-2-3-512",
	"BDNIgnorableUnicodeMode":   "all",
	"BDNAltSpaceIncludeVisible": "true",
}

var corpusAttrLists = [][]string{
	{"sAMAccountName", "objectSid", "memberOf"},
	{"*"},
	{},
	{"+", "createTimestamp", "cn", "supportedControl"},
	{"member;range=0-*", "cn", "1.1"},
}

var attrListChains = []string{"O", "C", "D", "G", "W", "w", "p", "E", "R", "r", "CR", "OCDGRr", "pE", "WR"}

var attrEntriesChains = []string{"O", "C", "R", "CR", "OCR"}

var corpusEntries = []string{"cn", "sn", "userAccountControl", "unicodePwd"}

type corpusCase struct {
	kind    string
	chain   string
	input   int
	options int
	seed    int64
}

func (c corpusCase) request(f Fixture) Request {
	r := Request{Kind: c.kind, Chain: c.chain, Options: f.OptionSets[c.options], Seed: c.seed, N: f.Samples}
	switch c.kind {
	case "filter":
		r.Input = f.Filters[c.input]
	case "basedn", "basedn_safe":
		r.Input = f.DNs[c.input]
	case "attrlist":
		r.Attrs = f.AttrLists[c.input]
	case "attrentries":
		r.Attrs = f.Entries
	}
	return r
}

func optionSets() []map[string]string {
	sets := []map[string]string{baseDNOptions}
	for _, options := range filterOptionSets {
		merged := map[string]string{"FiltObjCategoryRootDN": "DC=wonka,DC=lab"}
		for k, v := range options {
			merged[k] = v
		}
		sets = append(sets, merged)
	}
	return sets
}

func allFilters() []string {
	return append(append([]string{}, corpusFilters...), binaryFilters...)
}

func corpus() []corpusCase {
	var cases []corpusCase
	for _, seed := range seeds {
		for optionIndex := range filterOptionSets {
			for _, chain := range filterChains {
				for input := range allFilters() {
					if input >= len(corpusFilters) && strings.ContainsAny(chain, runeRebuildingCodes) {
						continue
					}
					cases = append(cases, corpusCase{"filter", chain, input, optionIndex + 1, seed})
				}
			}
		}
		for _, chain := range baseDNChains {
			for input := range corpusDNs {
				cases = append(cases, corpusCase{"basedn", chain, input, 0, seed})
				cases = append(cases, corpusCase{"basedn_safe", chain, input, 0, seed})
			}
		}
		for _, chain := range attrListChains {
			for input := range corpusAttrLists {
				cases = append(cases, corpusCase{"attrlist", chain, input, 0, seed})
			}
		}
		for _, chain := range attrEntriesChains {
			cases = append(cases, corpusCase{"attrentries", chain, 0, 0, seed})
		}
	}
	return cases
}
