import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Rawgithub_URL : FILE
{
	meta:
		description = "Detects executables containing URLs to raw contents of a Github gist"
		author = "ditekSHen"
		id = "5c1a9f66-11bd-545c-8cb1-53abd2cd872a"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L989-L999"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "07bde01e3a0f04d6333eade54a813ee0f331607a1b4b9bfcaeebce383e562557"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$url1 = "https://gist.githubusercontent.com/" ascii wide
		$url2 = "https://raw.githubusercontent.com/" ascii wide
		$raw = "/raw/" ascii wide

	condition:
		uint16(0)==0x5a4d and (($url1 and $raw) or ($url2))
}
