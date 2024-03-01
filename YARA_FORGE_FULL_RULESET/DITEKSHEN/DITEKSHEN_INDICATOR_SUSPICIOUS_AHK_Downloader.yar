import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_AHK_Downloader : FILE
{
	meta:
		description = "Detects AutoHotKey binaries acting as second stage droppers"
		author = "ditekSHen"
		id = "ac8320ed-a9e1-5660-a50f-ec010ac162a6"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L184-L196"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8806d8c03adb4ea4cd9b806f8f8c21e561b39b5602c70d09ed193e35e1502d35"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$d1 = "URLDownloadToFile, http" ascii
		$d2 = "URLDownloadToFile, file" ascii
		$s1 = ">AUTOHOTKEY SCRIPT<" fullword wide
		$s2 = "open \"%s\" alias AHK_PlayMe" fullword wide
		$s3 = /AHK\s(Keybd|Mouse)/ fullword wide

	condition:
		uint16(0)==0x5a4d and (1 of ($d*) and 1 of ($s*))
}
