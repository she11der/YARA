rule SIGNATURE_BASE_Pack_Injectt
{
	meta:
		description = "Webshells Auto-generated - file InjectT.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3a640c22-0cd4-5ab1-9216-c68625d7d505"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8071-L8086"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "983b74ccd57f6195a0584cdfb27d55e8"
		logic_hash = "9f66b7b429ed585888c0fb4943bb12262247b3af8d85bc67309b27752171e66a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "ail To Open Registry"
		$s4 = "32fDssignim"
		$s5 = "vide Internet S"
		$s6 = "d]Software\\M"
		$s7 = "TInject.Dll"

	condition:
		all of them
}
