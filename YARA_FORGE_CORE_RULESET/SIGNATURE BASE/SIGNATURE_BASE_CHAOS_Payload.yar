rule SIGNATURE_BASE_CHAOS_Payload : FILE
{
	meta:
		description = "Detects a CHAOS back connect payload"
		author = "Florian Roth (Nextron Systems)"
		id = "5057bc68-9bf8-54b4-88a1-d0c0cba62fa0"
		date = "2017-07-15"
		modified = "2023-12-05"
		reference = "https://github.com/tiagorlampert/CHAOS"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_chaos_payload.yar#L11-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ca409d3d0430fbc4c5ae52ce22616132da3a90c1ec3889571c6314e8787eee67"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0962fcfcb1b52df148720c2112b036e75755f09279e3ebfce1636739af9b4448"
		hash2 = "5c3553345f824b7b6de09ccb67d834e428b8df17443d98816471ca28f5a11424"

	strings:
		$x1 = { 2F 43 48 41 4F 53 00 02 73 79 6E 63 2F 61 74 6F 6D 69 63 }

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and all of them )
}
