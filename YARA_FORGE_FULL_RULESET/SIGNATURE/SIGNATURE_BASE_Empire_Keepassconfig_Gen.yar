rule SIGNATURE_BASE_Empire_Keepassconfig_Gen : FILE
{
	meta:
		description = "Detects Empire component - from files KeePassConfig.ps1, KeePassConfig.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "e2bc88c5-50f8-5ddc-a449-41929b1d0528"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L486-L500"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "986f299d2b6e2ec47acae09d8a25b6c45caf83c964208c594433308cd11ad264"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash2 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"

	strings:
		$s1 = "$KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)" fullword ascii

	condition:
		( uint16(0)==0x7223 and filesize <80KB and 1 of them ) or all of them
}
