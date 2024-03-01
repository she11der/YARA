import "pe"

rule SIGNATURE_BASE_SUSP_Imphash_Passrevealer_PY_EXE : FILE
{
	meta:
		description = "Detects an imphash used by password revealer and hack tools (some false positives with hardware driver installers)"
		author = "Florian Roth (Nextron Systems)"
		id = "9462dfc4-2feb-591d-ac0c-ba02f093c216"
		date = "2018-04-06"
		modified = "2021-11-09"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L4157-L4175"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "684e901eebf47e2bd8b25fd302963c2761376ce4754d74f9e6f1eb3024c89144"
		score = 40
		quality = 85
		tags = "FILE"
		hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"

	strings:
		$fp1 = "Assmann Electronic GmbH" ascii wide
		$fp2 = "Oculus VR" ascii wide
		$fp3 = "efm8load" ascii

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and pe.imphash()=="ed61beebc8d019dd9bec823e2d694afd" and not 1 of ($fp*)
}
