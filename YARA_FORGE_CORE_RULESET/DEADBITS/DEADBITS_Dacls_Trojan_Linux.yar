rule DEADBITS_Dacls_Trojan_Linux
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "bb83ba2b-70a3-5a0f-9588-d93b7f07f67f"
		date = "2020-01-07"
		modified = "2020-01-07"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/Dacls_Linux.yara#L1-L32"
		license_url = "N/A"
		logic_hash = "752d7daf9178e4fa20f2ce781c6ff70f83758f01479696f0808e1588da9a3d78"
		score = 75
		quality = 80
		tags = ""
		Author = "Adam M. Swanda"

	strings:
		$cls00 = "c_2910.cls" ascii fullword
		$cls01 = "k_3872.cls" ascii fullword
		$str00 = "{\"result\":\"ok\"}" ascii fullword
		$str01 = "SCAN  %s  %d.%d.%d.%d %d" ascii fullword
		$str02 = "/var/run/init.pid" ascii fullword
		$str03 = "/flash/bin/mountd" ascii fullword
		$str04 = "Name:" ascii fullword
		$str05 = "Uid:" ascii fullword
		$str06 = "Gid:" ascii fullword
		$str08 = "PPid:" ascii fullword
		$str09 = "session_id" ascii fullword

	condition:
		uint32be(0x0)==0x7f454c46 and (( all of ($cls*)) or ( all of ($str*)))
}
