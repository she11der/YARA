import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6D688Ecf46286Fe4B6823B91384Eca86 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4718996b-cb42-5b83-8fdf-d87751302a00"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2900-L2911"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "33296b5b9156af6d95bec9981a9fab3137bcd17bfb26ea2d212ae004275bf42e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "970205140b48d684d0dc737c0fe127460ccfac4f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AtomPark Software JSC" and pe.signatures[i].serial=="6d:68:8e:cf:46:28:6f:e4:b6:82:3b:91:38:4e:ca:86")
}
