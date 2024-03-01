rule SIGNATURE_BASE_Enigmapacker_Rare : FILE
{
	meta:
		description = "Detects an ENIGMA packed executable"
		author = "Florian Roth (Nextron Systems)"
		id = "748bc74c-e83f-5740-8ff7-f1371fc22802"
		date = "2017-04-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_enigma_protector.yar#L8-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a001b563db1b75581432d42a435683f24e244b6b354f83409b5b9d6d0314d63a"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "77be6e80a4cfecaf50d94ee35ddc786ba1374f9fe50546f1a3382883cb14cec9"

	strings:
		$s1 = "P.rel$oc$" fullword ascii
		$s2 = "ENIGMA" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <4000KB and all of them )
}
