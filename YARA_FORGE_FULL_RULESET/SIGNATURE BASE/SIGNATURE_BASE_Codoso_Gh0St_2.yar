rule SIGNATURE_BASE_Codoso_Gh0St_2 : FILE
{
	meta:
		description = "Detects Codoso APT Gh0st Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "5643d028-2a76-5bce-bf2f-8be706ab1fd5"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_codoso.yar#L152-L170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"
		logic_hash = "5864e52820578769a31a6925795d13283d7b3bc5f9ac50ac8aea6578a5919e71"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "cmd.exe /c ping 127.0.0.1 && ping 127.0.0.1 && sc start %s && ping 127.0.0.1 && sc start %s" fullword ascii
		$s1 = "rundll32.exe \"%s\", RunMeByDLL32" fullword ascii
		$s13 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
		$s14 = "%s -r debug 1" fullword ascii
		$s15 = "\\\\.\\keymmdrv1" fullword ascii
		$s17 = "RunMeByDLL32" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 1 of them
}
