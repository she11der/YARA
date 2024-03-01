rule SIGNATURE_BASE_CN_Tools_Vscan : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Vscan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2d73d9c9-62cd-592f-a44e-0a0456c85a3c"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1973-L1990"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0365fe05e2de0f327dfaa8cd0d988dbb7b379612"
		logic_hash = "2bbf0a3fb2b3fc9b646c6f8fc021f65a38e1b64edd74301481051541f8938902"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[+] Usage: VNC_bypauth <target> <scantype> <option>" fullword ascii
		$s2 = "========RealVNC <= 4.1.1 Bypass Authentication Scanner=======" fullword ascii
		$s3 = "[+] Type VNC_bypauth <target>,<scantype> or <option> for more informations" fullword ascii
		$s4 = "VNC_bypauth -i 192.168.0.1,192.168.0.2,192.168.0.3,..." fullword ascii
		$s5 = "-vn:%-15s:%-7d  connection closed" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and 2 of them
}
