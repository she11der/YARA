import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Regkeycomb_Disablewindefender : FILE
{
	meta:
		description = "Detects executables embedding registry key / value combination indicative of disabling Windows Defender features"
		author = "ditekSHen"
		id = "74c82d78-bdb3-54af-b04a-20d66ff123d7"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1446-L1468"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5a33052ded0823a8528590bd0da0023024db174f6f6a0766284c3195f5d3d41f"
		score = 40
		quality = 33
		tags = "FILE"
		importance = 20

	strings:
		$r1 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
		$k1 = "DisableAntiSpyware" ascii wide
		$r2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
		$k2 = "DisableBehaviorMonitoring" ascii wide
		$k3 = "DisableOnAccessProtection" ascii wide
		$k4 = "DisableScanOnRealtimeEnable" ascii wide
		$r3 = "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
		$k5 = "vDisableRealtimeMonitoring" ascii wide
		$r4 = "SOFTWARE\\Microsoft\\Windows Defender\\Spynet" ascii wide nocase
		$k6 = "SpyNetReporting" ascii wide
		$k7 = "SubmitSamplesConsent" ascii wide
		$r5 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
		$k8 = "TamperProtection" ascii wide
		$r6 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
		$k9 = "Add-MpPreference -ExclusionPath \"{0}\"" ascii wide

	condition:
		uint16(0)==0x5a4d and (1 of ($r*) and 1 of ($k*))
}
