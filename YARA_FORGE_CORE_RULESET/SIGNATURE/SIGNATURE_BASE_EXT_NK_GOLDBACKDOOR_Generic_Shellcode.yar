rule SIGNATURE_BASE_EXT_NK_GOLDBACKDOOR_Generic_Shellcode
{
	meta:
		description = "Generic detection for shellcode used to drop GOLDBACKDOOR"
		author = "Silas Cutler (silas@Stairwell.com)"
		id = "70081d63-0b26-5358-8444-5adc3a44aaa0"
		date = "2022-04-21"
		modified = "2023-12-05"
		reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_nk_goldbackdoor.yar#L44-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e046a70b1dee020ba73d960a9d91daaccd0b5c262965c8647f608c5c83a28257"
		score = 75
		quality = 85
		tags = ""
		version = "0.1"

	strings:
		$ = { B9 8E 8A DD 8D 8B F0 E8 ?? ?? ?? ?? FF D0 }
		$ = { B9 8E AB 6F 40 [1-10] 50 [1-10] E8 ?? ?? ?? ?? FF D0 }

	condition:
		all of them
}
