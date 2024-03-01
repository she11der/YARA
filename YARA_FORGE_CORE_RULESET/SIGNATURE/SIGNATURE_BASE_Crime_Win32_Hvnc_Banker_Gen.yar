import "pe"

rule SIGNATURE_BASE_Crime_Win32_Hvnc_Banker_Gen
{
	meta:
		description = "Detects malware banker hidden VNC"
		author = "@VK_Intel"
		id = "5e13f4a9-2231-524f-82b2-fbc6d6a43b6f"
		date = "2020-04-06"
		modified = "2023-12-05"
		reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_evilcorp_dridex_banker.yar#L22-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b01af685c3826834aadaf4eac1f1d8171db288a2efa7b769d8122421f7af8d7e"
		score = 75
		quality = 85
		tags = ""

	condition:
		pe.exports("VncStartServer") and pe.exports("VncStopServer")
}
