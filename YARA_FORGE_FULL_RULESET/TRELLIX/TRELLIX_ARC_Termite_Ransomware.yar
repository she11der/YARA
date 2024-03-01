rule TRELLIX_ARC_Termite_Ransomware : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect the Termite Ransomware"
		author = "McAfee ATR Team"
		id = "521ec8ee-a54c-57c3-9437-a2ef7f8ed4ca"
		date = "2018-08-28"
		modified = "2020-10-12"
		reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_termite.yar#L1-L32"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "021ca4692d3a721af510f294326a31780d6f8fcd9be2046d1c2a0902a7d58133"
		logic_hash = "e5c01e8377957fa25cf6c2031c2680e802b0082a36f50b97b4e488c5bf40e968"
		score = 75
		quality = 20
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Termite"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "C:\\Windows\\SysNative\\mswsock.dll" fullword ascii
		$s2 = "C:\\Windows\\SysWOW64\\mswsock.dll" fullword ascii
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Termite.exe" fullword ascii
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Payment.exe" fullword ascii
		$s5 = "C:\\Windows\\Termite.exe" fullword ascii
		$s6 = "\\Shell\\Open\\Command\\" fullword ascii
		$s7 = "t314.520@qq.com" fullword ascii
		$s8 = "(*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <6000KB) and all of them
}
