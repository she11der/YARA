rule SIGNATURE_BASE_Apt_RU_Moonlightmaze_De_Tool
{
	meta:
		description = "Rule to detect Moonlight Maze 'de' and 'deg' tunnel tool"
		author = "Kaspersky Lab"
		id = "09bfebca-7cec-5514-9f48-c0c2c57efcf9"
		date = "2017-03-27"
		modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_moonlightmaze.yar#L111-L137"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4bc7ed168fb78f0dc688ee2be20c9703"
		hash = "8b56e8552a74133da4bc5939b5f74243"
		logic_hash = "f658e1aa2ddb84fe3c1de7c7c00f2148d232cf2b3381c298420abfc382c02986"
		score = 75
		quality = 85
		tags = ""
		version = "1.0"

	strings:
		$a1 = "Vnuk: %d" ascii fullword
		$a2 = "Syn: %d" ascii fullword
		$a3 = {25 73 0A 25 73 0A 25 73 0A 25 73 0A}

	condition:
		((2 of ($a*)))
}
