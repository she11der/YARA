rule SIGNATURE_BASE_Mithril_V1_45_Dlltest
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "2aea84b6-1b51-58cd-b52b-c31b1f75d295"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8286-L8299"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
		logic_hash = "cf1e2ca39ae6b726792bbbaf0f1dd90788a4bb9ba5e3d50c22d75f2b3d4e9e7d"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "syspath"
		$s4 = "\\Mithril"
		$s5 = "--list the services in the computer"

	condition:
		all of them
}
