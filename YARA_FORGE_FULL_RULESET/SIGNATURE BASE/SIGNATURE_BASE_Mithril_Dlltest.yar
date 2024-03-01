rule SIGNATURE_BASE_Mithril_Dlltest
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "59a6bfb6-c099-56cd-b40e-3e92ea0eb7d3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8530-L8542"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"
		logic_hash = "c8c8d1b75ed4eb4bc66a762e53aa6b3ab439e96ef464a8b9ffa4dff887986465"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "please enter the password:"
		$s3 = "\\dllTest.pdb"

	condition:
		all of them
}
