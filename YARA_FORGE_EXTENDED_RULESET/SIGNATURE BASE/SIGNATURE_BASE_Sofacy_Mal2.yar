import "pe"

rule SIGNATURE_BASE_Sofacy_Mal2 : FILE
{
	meta:
		description = "Sofacy Group Malware Sample 2"
		author = "Florian Roth (Nextron Systems)"
		id = "1547cc67-7d7c-5ec9-816c-15b7d523376a"
		date = "2015-06-19"
		modified = "2023-12-05"
		reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sofacy_xtunnel_bundestag.yar#L50-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "566ab945f61be016bfd9e83cc1b64f783b9b8deb891e6d504d3442bc8281b092"
		logic_hash = "c325ed815b7de3338363d064f4097edf0596644d4ef8d642fda3664a2a16c2eb"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "PROJECT\\XAPS_OBJECTIVE_DLL\\" ascii
		$x2 = "XAPS_OBJECTIVE.dll" fullword ascii
		$s1 = "i`m wait" fullword ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*)) and $s1
}
