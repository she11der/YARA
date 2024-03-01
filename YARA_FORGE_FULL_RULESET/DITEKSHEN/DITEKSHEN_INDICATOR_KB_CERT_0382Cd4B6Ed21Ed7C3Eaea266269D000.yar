import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0382Cd4B6Ed21Ed7C3Eaea266269D000 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ad4bc1bc-4d72-51bf-a22c-cd98f33f3931"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2612-L2623"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7e8204f2ec30da73bc2eb83e065412c96e084d7ff5f8ab6125d643693d7407d1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e600612ffcd002718b7d03a49d142d07c5a04154"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LOOK AND FEEL SP Z O O" and pe.signatures[i].serial=="03:82:cd:4b:6e:d2:1e:d7:c3:ea:ea:26:62:69:d0:00")
}
