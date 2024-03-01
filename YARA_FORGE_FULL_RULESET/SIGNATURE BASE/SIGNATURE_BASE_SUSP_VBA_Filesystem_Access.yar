rule SIGNATURE_BASE_SUSP_VBA_Filesystem_Access : FILE
{
	meta:
		description = "Detects suspicious VBA that writes to disk and is activated on document open"
		author = "Florian Roth (Nextron Systems)"
		id = "91241b91-ca3f-5817-bf78-550fe015b467"
		date = "2019-06-21"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_office_dropper.yar#L82-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "13d7e0708968a7700308e6216ea5d0a396f9335137ae1e33c3b34a2f54012ec6"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"

	strings:
		$s1 = "\\Common Files\\Microsoft Shared\\" wide
		$s2 = "Scripting.FileSystemObject" ascii
		$a1 = "Document_Open" ascii
		$a2 = "WScript.Shell" ascii
		$a3 = "AutoOpen" fullword ascii

	condition:
		uint16(0)==0xcfd0 and filesize <100KB and all of ($s*) and 1 of ($a*)
}
