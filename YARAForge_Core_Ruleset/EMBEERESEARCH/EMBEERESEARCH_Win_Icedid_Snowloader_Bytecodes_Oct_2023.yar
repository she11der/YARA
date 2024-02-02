rule EMBEERESEARCH_Win_Icedid_Snowloader_Bytecodes_Oct_2023
{
	meta:
		description = "No description has been set in the source file - EmbeeResearch"
		author = "Matthew @ Embee_Research"
		id = "ad5d7bf5-813d-519d-91ae-e6a69fd557df"
		date = "2023-08-27"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/d4226e586a49cd4d1eede9a58738509689cf059f/Rules/win_icedid_snowloader_bytecodes_oct_2023.yar#L2-L23"
		license_url = "N/A"
		hash = "e096de90f65ff83ed0e929b330aa765a8e2322625325fb042775bff1748467cc"
		hash = "e87928fcddf13935c91a0b5577e28efd29bb6a5c1d98e5129dec63e231601053"
		hash = "82a01607ebdcaa73b9ff201ccb76780ad8de4a99dd3df026dcb71b0f007456ed"
		logic_hash = "5baa308ce130cbbe80f94fc127b083f26ae87552910c2bc6f3bae3008cf1aa63"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s_1 = {4c 77 26 07}
		$s_2 = {58 a4 53 e5}
		$s_3 = {10 e1 8a c3}

	condition:
		( all of ($s*)) and pe.number_of_exports>20
}