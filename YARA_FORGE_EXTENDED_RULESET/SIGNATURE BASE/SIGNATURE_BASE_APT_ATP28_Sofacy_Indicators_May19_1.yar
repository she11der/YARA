import "pe"

rule SIGNATURE_BASE_APT_ATP28_Sofacy_Indicators_May19_1 : FILE
{
	meta:
		description = "Detects APT28 Sofacy indicators in samples"
		author = "Florian Roth (Nextron Systems)"
		id = "ca768b60-7094-537a-b848-28bd42555287"
		date = "2019-05-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1129647994603790338"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sofacy.yar#L53-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4e3530f540cc66e99b82bd88887943c8e524d4d750734058d9a7b27f76bc6871"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "80548416ffb3d156d3ad332718ed322ef54b8e7b2cc77a7c5457af57f51d987a"
		hash2 = "b40909ac0b70b7bd82465dfc7761a6b4e0df55b894dd42290e3f72cb4280fa44"

	strings:
		$x1 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/cert.pem" ascii
		$x2 = "C:\\Users\\User\\Desktop\\Downloader_Poco" ascii
		$s1 = "w%SystemRoot%\\System32\\npmproxy.dll" fullword wide
		$op0 = { e8 41 37 f6 ff 48 2b e0 e8 99 ff ff ff 48 8b d0 }
		$op1 = { e9 34 3c e3 ff cc cc cc cc 48 8d 8a 20 }
		$op2 = { e8 af bb ef ff b8 ff ff ff ff e9 f4 01 00 00 8b }

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and (pe.imphash()=="f4e1c3aaec90d5dfa23c04da75ac9501" or 1 of ($x*) or ($s1 and 2 of ($op*)))
}
