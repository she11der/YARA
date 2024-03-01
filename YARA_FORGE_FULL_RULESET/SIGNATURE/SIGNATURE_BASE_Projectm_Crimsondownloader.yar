rule SIGNATURE_BASE_Projectm_Crimsondownloader : FILE
{
	meta:
		description = "Detects ProjectM Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "2e0658c9-a93d-5eef-93a2-eb1ab29acaee"
		date = "2016-03-26"
		modified = "2023-12-05"
		reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_project_m.yar#L32-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "dc8bd60695070152c94cbeb5f61eca6e4309b8966f1aa9fdc2dd0ab754ad3e4c"
		logic_hash = "3c9a4f5aca4c9fc26d371027a32e349a456ef25d6b403a66b9afb1ee19dd4d00"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "E:\\Projects\\m_project\\main\\mj shoaib"
		$s1 = "\\obj\\x86\\Debug\\secure_scan.pdb" ascii
		$s2 = "secure_scan.exe" fullword wide
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|mswall" fullword wide
		$s4 = "secure_scan|mswall" fullword wide
		$s5 = "[Microsoft-Security-Essentials]" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and $x1) or ( all of them )
}
