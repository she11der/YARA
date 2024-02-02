rule SIGNATURE_BASE_Opcloudhopper_Wmidll_Inmemory
{
	meta:
		description = "Malware related to Operation Cloud Hopper - Page 25"
		author = "Florian Roth (Nextron Systems)"
		id = "0afb6e52-bc9a-5a68-890b-79a017e5d554"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_cloudhopper.yar#L281-L293"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6dddda4e519eeaa67eb4c21151cab10553420a23a077751e0fc45fcae0bf6e69"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "wmi.dll 2>&1" ascii

	condition:
		all of them
}