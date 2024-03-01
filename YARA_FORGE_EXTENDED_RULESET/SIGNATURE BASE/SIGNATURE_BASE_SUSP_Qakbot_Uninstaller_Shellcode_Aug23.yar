rule SIGNATURE_BASE_SUSP_Qakbot_Uninstaller_Shellcode_Aug23
{
	meta:
		description = "Detects Qakbot Uninstaller files used by the FBI and Dutch National Police in a disruption operation against the Qakbot in August 2023"
		author = "Florian Roth"
		id = "860796ab-689f-5c5f-bc40-3e2ef7fd1d5d"
		date = "2023-08-30"
		modified = "2023-12-05"
		reference = "https://www.justice.gov/usao-cdca/divisions/national-security-division/qakbot-resources"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_qakbot_uninstaller.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "91d26c50bf29517aa68e709ca3b6f32f4ca390f4c2f48e48cd251bfdd5dbcc71"
		score = 60
		quality = 85
		tags = ""

	strings:
		$xc1 = { E8 00 00 00 00 58 55 89 E5 89 C2 68 03 00 00 00 68 00 2C 00 00 05 20 0A 00 00 50 E8 05 00 00 00 83 C4 04 C9 C3 81 EC 08 01 00 00 53 55 56 57 6A 6B 58 6A 65 5B 6A 72 66 89 84 24 D4 00 00 00 33 }

	condition:
		$xc1
}
