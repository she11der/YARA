rule SIGNATURE_BASE_SUSP_VHD_Suspicious_Small_Size : FILE
{
	meta:
		description = "Detects suspicious VHD files"
		author = "Florian Roth (Nextron Systems)"
		id = "f4a72e7b-ddd3-5038-9440-1e81dc27755d"
		date = "2019-12-21"
		modified = "2023-01-27"
		reference = "https://twitter.com/MeltX0R/status/1208095892877774850"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_vhd_anomaly.yar#L2-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0bd5b113714854feaa89d52d4bab6a4a00f0dcb7fd816fa7b036eb43d3ea0dd8"
		score = 50
		quality = 83
		tags = "FILE"
		hash1 = "3382a75bd959d2194c4b1a8885df93e8770f4ebaeaff441a5180ceadf1656cd9"

	strings:
		$hc1 = { 63 6F 6E 65 63 74 69 78 }
		$hc2a = { 49 6E 76 61 6C 69 64 20 70 61 72 74 69 74 69 6F
               6E 20 74 61 62 6C 65 00 45 72 72 6F 72 20 6C 6F
               61 64 69 6E 67 20 6F 70 65 72 61 74 69 6E 67 20
               73 79 73 74 65 6D 00 4D 69 73 73 69 6E 67 20 6F
               70 65 72 61 74 69 6E 67 20 73 79 73 74 65 6D }
		$hc2b = "connectix"

	condition:
		not uint16(0)==0x5a4d and filesize >1KB and filesize <=4000KB and ($hc1 at 0 or all of ($hc2*))
}
