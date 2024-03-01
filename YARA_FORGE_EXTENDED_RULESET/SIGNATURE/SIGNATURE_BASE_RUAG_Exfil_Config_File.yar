rule SIGNATURE_BASE_RUAG_Exfil_Config_File : FILE
{
	meta:
		description = "Detects a config text file used in data exfiltration in RUAG case"
		author = "Florian Roth (Nextron Systems)"
		id = "7057bc7b-7f8c-5db8-b7f3-f6c33487b122"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://goo.gl/N5MEj0"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_ruag.yar#L73-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "379e8762932ca565f3bd35ec241aef2d0445fbe6182a041e4d4e16a1170202ef"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$h1 = "[TRANSPORT]" ascii
		$s1 = "system_pipe" ascii
		$s2 = "spstatus" ascii
		$s3 = "adaptable" ascii
		$s4 = "post_frag" ascii
		$s5 = "pfsgrowperiod" ascii

	condition:
		uint32(0)==0x4152545b and $h1 at 0 and all of ($s*) and filesize <1KB
}
