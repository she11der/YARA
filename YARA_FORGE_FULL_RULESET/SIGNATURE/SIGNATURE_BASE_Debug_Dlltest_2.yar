rule SIGNATURE_BASE_Debug_Dlltest_2
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "cf81e3de-513c-584d-bc37-6504e91b170c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8572-L8584"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
		logic_hash = "bf260ce0f8d4728920679573cd77927b44db28ba6102923707af8d1ad7d0ef2d"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "\\Debug\\dllTest.pdb"
		$s5 = "--list the services in the computer"

	condition:
		all of them
}
