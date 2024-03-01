import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_PWS_Capturescreenshot
{
	meta:
		description = "Detects PowerShell script with screenshot capture capability"
		author = "ditekSHen"
		id = "d769936a-a81d-5052-8b1b-7bd5a73b41db"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2365-L2377"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "26e02d7dc242fb2c913b3a7c07e92c84becad62a4cdbae781bce948bfe0eb81b"
		score = 40
		quality = 45
		tags = ""
		importance = 20

	strings:
		$encoder = ".ImageCodecInfo]::GetImageEncoders(" ascii nocase
		$capture1 = ".Sendkeys]::SendWait(\"{PrtSc}\")" ascii nocase
		$capture2 = ".Sendkeys]::SendWait('{PrtSc}')" ascii nocase
		$access = ".Clipboard]::GetImage(" ascii nocase
		$save = ".Save(" ascii nocase

	condition:
		$encoder and (1 of ($capture*) and ($access or $save))
}
