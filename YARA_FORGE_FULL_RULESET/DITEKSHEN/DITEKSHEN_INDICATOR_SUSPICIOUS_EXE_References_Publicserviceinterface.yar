import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_References_Publicserviceinterface : FILE
{
	meta:
		description = "Detect executables referencing public and free service interface testing and dev services as means of CnC"
		author = "ditekSHen"
		id = "f6ac752b-0afc-5834-82b4-4dbcfded2f3a"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2448-L2459"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2a7b4fe7ddb41a7ae895a2ac8e9bb5eda61f5b86ca35575be32d65611e2d0a9e"
		score = 40
		quality = 37
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "mockbin.org/bin" ascii wide nocase
		$s2 = "run.mocky.io/v3" ascii wide nocase
		$s3 = "webhook.site/" ascii wide nocase
		$s4 = "devtunnels.ms/" ascii wide nocase

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f or uint16(0)==0xfacf) and 1 of them
}
