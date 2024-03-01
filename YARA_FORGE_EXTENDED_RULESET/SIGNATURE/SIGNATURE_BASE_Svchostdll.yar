rule SIGNATURE_BASE_Svchostdll
{
	meta:
		description = "Webshells Auto-generated - file svchostdll.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "b369d702-1f29-56ec-a742-f87d9c42c775"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7431-L7450"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0f6756c8cb0b454c452055f189e4c3f4"
		logic_hash = "4a7a7bb7d827c2e7801f8c33b292bb3d312428fc4ae79f07e103f456984c3b83"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "InstallService"
		$s1 = "RundllInstallA"
		$s2 = "UninstallService"
		$s3 = "&G3 Users In RegistryD"
		$s4 = "OL_SHUTDOWN;I"
		$s5 = "SvcHostDLL.dll"
		$s6 = "RundllUninstallA"
		$s7 = "InternetOpenA"
		$s8 = "Check Cloneomplete"

	condition:
		all of them
}
