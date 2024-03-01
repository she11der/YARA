rule SIGNATURE_BASE_OPCLEAVER_Ccproxy_Config
{
	meta:
		description = "CCProxy config known from Operation Cleaver"
		author = "Florian Roth (Nextron Systems)"
		id = "c4d80a2a-2a32-585e-bc20-1c5118e4ee48"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cleaver.yar#L334-L352"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6e5c1c75a499434ad6ddd2439d28ac91d500b18418e693761d0b236bf6d6ce42"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "UserName=User-001" fullword ascii
		$s2 = "Web=1" fullword ascii
		$s3 = "Mail=1" fullword ascii
		$s4 = "FTP=0" fullword ascii
		$x1 = "IPAddressLow=78.109.194.114" fullword ascii

	condition:
		all of ($s*) or $x1
}
