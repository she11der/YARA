rule SIGNATURE_BASE_CN_Honker_Manualinjection : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ManualInjection.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f0899003-824f-56ed-b653-9f7a77b9ec6a"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L720-L735"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e83d427f44783088a84e9c231c6816c214434526"
		logic_hash = "fe8eba3b79f5bc4cf820ff51816c3f2a27d6ed8f6ab3963f88a3232c9a4b5c1e"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "http://127.0.0.1/cookie.asp?fuck=" fullword ascii
		$s16 = "http://Www.cnhuker.com | http://www.0855.tv" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
