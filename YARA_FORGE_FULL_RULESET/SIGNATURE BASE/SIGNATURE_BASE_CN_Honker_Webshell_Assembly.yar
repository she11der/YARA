rule SIGNATURE_BASE_CN_Honker_Webshell_Assembly : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file assembly.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "7639e81d-fe21-5a12-9a20-fe894eefef73"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L301-L315"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2bcb4d22758b20df6b9135d3fb3c8f35a9d9028e"
		logic_hash = "34dc47b2f91a15a62175f3cab88d5ff24d2a3aa62f74fb9e43a4aaae96ced999"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "response.write oScriptlhn.exec(\"cmd.exe /c\" & request(\"c\")).stdout.readall" fullword ascii

	condition:
		filesize <1KB and all of them
}
