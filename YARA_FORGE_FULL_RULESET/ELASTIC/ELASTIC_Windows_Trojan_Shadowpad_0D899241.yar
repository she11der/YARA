rule ELASTIC_Windows_Trojan_Shadowpad_0D899241 : MEMORY
{
	meta:
		description = "Target ShadowPad payload"
		author = "Elastic Security"
		id = "0d899241-6ef8-4524-a728-4ed53e4d2cec"
		date = "2023-01-31"
		modified = "2023-02-01"
		reference = "https://www.elastic.co/security-labs/update-to-the-REF2924-intrusion-set-and-related-campaigns"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_ShadowPad.yar#L23-L48"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "cb3a425565b854f7b892e6ebfb3734c92418c83cd590fc1ee9506bcf4d8e02ea"
		logic_hash = "57385e149c6419aed2dcd3ecbbe26d8598918395a6480dd5cdb799ce7328901a"
		score = 75
		quality = 25
		tags = "MEMORY"
		fingerprint = "7070eb3608c2c39804ccad4a05e4de12ec4eb47388589ef72c723b353b920a68"
		threat_name = "Windows.Trojan.ShadowPad"
		severity = 100
		arch_context = "x86"
		scan_context = "memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "hH#whH#w" fullword
		$a2 = "Yuv~YuvsYuvhYuv]YuvRYuvGYuv1:tv<Yuvb#tv1Yuv-8tv&Yuv" fullword
		$a3 = "pH#wpH#w" fullword
		$a4 = "HH#wHH#wA" fullword
		$a5 = "xH#wxH#w:$" fullword
		$re1 = /(HTTPS|TCP|UDP):\/\/[^:]+:443/

	condition:
		4 of them
}
