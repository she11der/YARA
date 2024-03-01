import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_56Bba7Fe242E6B49695Bcf07870F5F5E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "902c1949-81e6-5070-ac60-2ebbb363fc6d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5047-L5058"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6c9da28b90bcff069509fc8e91c0a960805bb8339d0fa21f5466c38b6d20f95f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3c176bff246a30460311e8c71f880cad2a845164"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ewGMiQgCHj" and pe.signatures[i].serial=="56:bb:a7:fe:24:2e:6b:49:69:5b:cf:07:87:0f:5f:5e")
}
