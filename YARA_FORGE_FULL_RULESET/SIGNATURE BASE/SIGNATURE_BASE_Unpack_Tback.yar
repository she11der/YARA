rule SIGNATURE_BASE_Unpack_Tback
{
	meta:
		description = "Webshells Auto-generated - file TBack.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "b5f93621-e1e9-5aed-b574-471b4c1f9570"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7340-L7351"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a9d1007823bf96fb163ab38726b48464"
		logic_hash = "0fb43766c305f4235cc0987f411fdc3b3674723687f0b63d346429f4a7b5b87f"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "\\final\\new\\lcc\\public.dll"

	condition:
		all of them
}
