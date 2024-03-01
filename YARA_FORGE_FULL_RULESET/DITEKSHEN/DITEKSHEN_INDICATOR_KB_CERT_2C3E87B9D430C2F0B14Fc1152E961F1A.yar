import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2C3E87B9D430C2F0B14Fc1152E961F1A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8e686e58-8fc5-50cf-9259-dcd70f5cc27b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3017-L3028"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "43a8f2d9055091f930af456abd334e38fb6a98bee3bfb8dcbf84c9563c777101"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "80daa4ad14fc420d7708f2855e6fab085ca71980"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Abfaacccde" and pe.signatures[i].serial=="2c:3e:87:b9:d4:30:c2:f0:b1:4f:c1:15:2e:96:1f:1a")
}
