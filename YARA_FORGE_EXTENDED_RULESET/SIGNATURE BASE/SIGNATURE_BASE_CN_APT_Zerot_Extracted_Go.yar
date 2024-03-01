rule SIGNATURE_BASE_CN_APT_Zerot_Extracted_Go : FILE
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT  - file Go.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ba929e6d-4162-58e7-b8a8-bcb066b64522"
		date = "2017-02-04"
		modified = "2023-01-06"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_cn_pp_zerot.yar#L180-L203"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "bf5e2d825e4bd63e94455ffb4013fa1088098a826390c1916c0aa50866588fcb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "83ddc69fe0d3f3d2f46df7e72995d59511c1bfcca1a4e14c330cb71860b4806b"

	strings:
		$x1 = "%s\\cmd.exe /c %s\\Zlh.exe" fullword ascii
		$x2 = "\\BypassUAC.VS2010\\Release\\" ascii
		$s1 = "Zjdsf.exe" fullword ascii
		$s2 = "SS32prep.exe" fullword ascii
		$s3 = "windowsgrep.exe" fullword ascii
		$s4 = "Sysdug.exe" fullword ascii
		$s5 = "Proessz.exe" fullword ascii
		$s6 = "%s\\Zlh.exe" fullword ascii
		$s7 = "/C %s\\%s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 3 of ($s*))) or (7 of them )
}
