rule SIGNATURE_BASE_RAT_Blackshades : BLACKSHADES
{
	meta:
		description = "Detects BlackShades RAT"
		author = "Brian Wallace (@botnet_hunter)"
		id = "039f9efd-034d-5088-9a2f-7a63ad170d3d"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L144-L161"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "23f8d52cf92b594f9302d549cf54f37dc0a01b5686da74b72120a8072435abfe"
		score = 75
		quality = 85
		tags = "BLACKSHADES"
		family = "blackshades"

	strings:
		$string1 = "bss_server"
		$string2 = "txtChat"
		$string3 = "UDPFlood"

	condition:
		all of them
}
